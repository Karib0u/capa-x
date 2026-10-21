//! Development tool: regenerate the compact decompiler runtime PAT database.
//! Run from the repository root and redirect stdout to a temporary file first.
use lancelot_flirt::{FlirtSignature, SigElement, Symbol};

fn root(signature: &FlirtSignature) -> Option<&str> {
    signature.names.iter().find_map(|symbol| {
        let name = match symbol {
            Symbol::Public(name) | Symbol::Local(name) | Symbol::Reference(name) => name,
        };
        (name.offset == 0).then_some(name.name.as_str())
    })
}
fn overlapping_heads(left: &FlirtSignature, right: &FlirtSignature) -> bool {
    left.byte_sig
        .0
        .iter()
        .zip(&right.byte_sig.0)
        .all(|(a, b)| !matches!((a, b), (SigElement::Byte(a), SigElement::Byte(b)) if a != b))
}
fn main() -> anyhow::Result<()> {
    let bytes = include_bytes!("../sigs/1_flare_msvc_rtf_32_64.sig");
    let signatures = lancelot_flirt::sig::parse(bytes)?;
    let mut kept = 0;
    for signature in &signatures {
        let Some(name) = root(signature) else {
            continue;
        };
        if !matches!(
            name.trim_start_matches('_'),
            "security_init_cookie" | "security_check_cookie" | "DllMainCRTStartup" | "DllMain"
        ) {
            continue;
        }
        // Keep only self-contained, unambiguous patterns. Rejecting every head
        // overlap with a different root is deliberately conservative: removing
        // other database entries must not turn an ambiguous match into a name.
        if signature
            .names
            .iter()
            .any(|s| matches!(s, Symbol::Reference(_)))
            || signatures
                .iter()
                .any(|other| root(other) != Some(name) && overlapping_heads(signature, other))
        {
            continue;
        }
        anyhow::ensure!(
            signature.byte_sig.0.len() <= usize::from(signature.byte_sig_size),
            "SIG prefix exceeds its declared CRC start for {name}"
        );
        let mut signature = signature.clone();
        // SIG prefixes may omit trailing wildcards, but PAT derives the CRC
        // start from the rendered prefix length. Preserve that offset exactly.
        signature
            .byte_sig
            .0
            .resize(usize::from(signature.byte_sig_size), SigElement::Wildcard);
        let rendered = signature.render_pat();
        let parsed = lancelot_flirt::pat::parse(&format!("{rendered}\n---\n"))?;
        anyhow::ensure!(
            parsed.len() == 1
                && parsed.first().map(FlirtSignature::render_pat).as_deref()
                    == Some(rendered.as_str()),
            "PAT round trip changed constraints for {name}"
        );
        println!("{rendered}");
        kept += 1;
    }
    println!("---");
    eprintln!("Retained {kept} self-contained runtime signatures");
    Ok(())
}
