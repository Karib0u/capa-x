//! Development tool: compare the FID hasher with Ghidra's output
//! (`scripts/decompiler_fid/DumpFidHashes.java`). Usage: fid_truth [--bits=32] TRUTH.tsv...
//! Reports per-instruction mask and operand disagreements and function hash agreement.
use capa_x::fid::{
    hash::{hash_function, Instruction, Obj},
    x86,
};
use std::collections::BTreeMap;

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap_or(0))
        .collect()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn objects(operand: &capa_x::fid::hash::Operand) -> String {
    operand
        .objects
        .iter()
        .map(|o| match o {
            Obj::Scalar(v) => format!("S{v},"),
            Obj::Register(r) => format!("R{r},"),
            Obj::Address => "A,".to_owned(),
        })
        .collect()
}

fn main() {
    let mut insn_total = 0_usize;
    let mut mask_bad = 0_usize;
    let mut ops_bad = 0_usize;
    let mut undecoded = 0_usize;
    let mut classes: BTreeMap<String, (usize, String)> = BTreeMap::new();
    let (mut funcs, mut good, mut bad_funcs) = (0_usize, 0_usize, 0_usize);
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let bits: u32 = if arguments.iter().any(|a| a == "--bits=32") {
        32
    } else {
        64
    };
    for path in arguments.iter().filter(|a| !a.starts_with("--")) {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        // 32-bit operands are typed as addresses when they point into the image, so the
        // sample itself is needed: FID_SAMPLES is the directory holding TRUTH's stem.
        let ranges: Vec<(u64, u64)> = std::env::var("FID_SAMPLES")
            .ok()
            .and_then(|dir| {
                let stem = std::path::Path::new(path)
                    .file_name()?
                    .to_str()?
                    .strip_suffix(".tsv")?
                    .to_owned();
                let image = capa_x::extract::image::LoadedImage::parse(
                    &std::fs::read(format!("{dir}/{stem}")).ok()?,
                )
                .ok()?;
                Some(
                    image
                        .sections
                        .iter()
                        .map(|s| (s.address, s.address + s.virtual_size))
                        .collect(),
                )
            })
            .unwrap_or_default();
        let is_address = |value: u64| {
            ranges
                .iter()
                .any(|(start, end)| *start <= value && value < *end)
        };
        let mut current: Option<(String, Vec<String>)> = None;
        let mut block: Vec<Instruction> = Vec::new();
        let mut block_ok = true;
        let mut flush =
            |header: &Option<(String, Vec<String>)>, block: &mut Vec<Instruction>, ok: bool| {
                if let Some((_, fields)) = header {
                    funcs += 1;
                    if ok {
                        let quad = hash_function(block, &|_, _| false);
                        let want = (
                            fields[2].clone(),
                            fields[3].clone(),
                            fields[4].clone(),
                            fields[5].clone(),
                        );
                        let got = quad.map(|q| {
                            (
                                q.code_units.to_string(),
                                format!("{:x}", q.full_hash),
                                q.specific_additional.to_string(),
                                format!("{:x}", q.specific_hash),
                            )
                        });
                        if got.as_ref() == Some(&want) {
                            good += 1
                        } else {
                            bad_funcs += 1
                        }
                    } else {
                        bad_funcs += 1;
                    }
                }
                block.clear();
            };
        for line in text.lines() {
            let f: Vec<&str> = line.split('\t').collect();
            if f[0] == "F" {
                flush(&current, &mut block, block_ok);
                block_ok = true;
                current = Some((
                    f[1].to_owned(),
                    f.iter().map(|s| s.to_string()).collect::<Vec<_>>()[1..].to_vec(),
                ));
                // fields: entry name cus fh specAdd specHash count -> index shift
                continue;
            }
            if f[0] != "I" || f.len() < 7 {
                continue;
            }
            insn_total += 1;
            let address = u64::from_str_radix(f[2], 16).unwrap_or(0);
            let raw = unhex(f[3]);
            let want_mask = unhex(f[4]);
            let Some(ours) = x86::describe_in(bits, address, &raw, &is_address) else {
                undecoded += 1;
                block_ok = false;
                let key = format!("undecoded {}", &f[3][..f[3].len().min(6)]);
                classes.entry(key).or_insert((0, f[3].to_owned())).0 += 1;
                continue;
            };
            let mut ok = true;
            // Compare the masked bytes: they are what the hash consumes.
            let want_masked: Vec<u8> = raw.iter().zip(&want_mask).map(|(b, m)| b & m).collect();
            if ours.masked != want_masked {
                mask_bad += 1;
                ok = false;
                let key = format!("mask {}", &f[3][..f[3].len().min(6)]);
                classes
                    .entry(key)
                    .or_insert((
                        0,
                        format!("{} want {} got {}", f[3], f[4], hex(&ours.masked)),
                    ))
                    .0 += 1;
            }
            let mut want_ops = String::new();
            let mut want_flags = Vec::new();
            for part in f.get(6).unwrap_or(&"").split('|').filter(|s| !s.is_empty()) {
                let (head, objs) = part.split_once(':').unwrap_or((part, ""));
                let ty =
                    u32::from_str_radix(head.split('/').next().unwrap_or("0"), 16).unwrap_or(0);
                want_flags.push((ty & 0x4000 != 0, ty & 0x2000 != 0));
                want_ops.push_str(objs);
                want_ops.push('|');
            }
            let got_ops: String = ours
                .operands
                .iter()
                .map(|o| format!("{}|", objects(o)))
                .collect();
            if got_ops != want_ops {
                ops_bad += 1;
                ok = false;
                let key = format!("ops {}", &f[3][..f[3].len().min(4)]);
                classes
                    .entry(key)
                    .or_insert((0, format!("{} want {} got {}", f[3], want_ops, got_ops)))
                    .0 += 1;
            } else {
                for (operand, (scalar, address_flag)) in ours.operands.iter().zip(&want_flags) {
                    let relevant = operand.objects.iter().any(|o| matches!(o, Obj::Scalar(_)));
                    if relevant && operand.whole_scalar != *scalar {
                        ok = false;
                        ops_bad += 1;
                        let key = format!("scalarflag {}", &f[3][..f[3].len().min(4)]);
                        classes
                            .entry(key)
                            .or_insert((
                                0,
                                format!(
                                    "{} want scalar={} got {} ({})",
                                    f[3], scalar, operand.whole_scalar, f[6]
                                ),
                            ))
                            .0 += 1;
                    } else if relevant && operand.whole_scalar && operand.address != *address_flag {
                        ok = false;
                        ops_bad += 1;
                        let key = format!("addrflag {}", &f[3][..f[3].len().min(4)]);
                        classes
                            .entry(key)
                            .or_insert((
                                0,
                                format!(
                                    "{} want addr={} got {} ({})",
                                    f[3], address_flag, operand.address, f[6]
                                ),
                            ))
                            .0 += 1;
                    }
                }
            }
            if !ok {
                block_ok = false;
            }
            let mut ours = ours;
            ours.is_call = f[5] == "1";
            block.push(ours);
        }
        flush(&current, &mut block, block_ok);
    }
    println!(
        "instructions {insn_total} undecoded {undecoded} mask-bad {mask_bad} ops-bad {ops_bad}"
    );
    println!("functions {funcs} hash-equal {good} not-equal {bad_funcs}");
    let mut sorted: Vec<_> = classes.into_iter().collect();
    sorted.sort_by_key(|entry| std::cmp::Reverse(entry.1 .0));
    for (key, (count, example)) in sorted.into_iter().take(60) {
        println!("{count:6} {key:24} {example}");
    }
}
