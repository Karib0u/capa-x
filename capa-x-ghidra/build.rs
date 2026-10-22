#[cfg(feature = "native")]
mod native {
    use std::{env, fs, path::PathBuf, process::Command};

    const CORE: &str = "xml marshal space float address pcoderaw translate opcodes globalcontext";
    const SLEIGH: &str = "sleigh pcodeparse pcodecompile sleighbase slghsymbol slghpatexpress slghpattern semantics context slaformat compression filemanage";
    const DECOMP: &str = "capability architecture options graph cover block cast typeop database cpool comment stringmanage modelrules fspec action loadimage grammar varnode op type variable varmap jumptable emulate emulateutil flow userop expression multiprecision funcdata funcdata_block funcdata_op funcdata_varnode unionresolve pcodeinject heritage prefersplit rangeutil ruleaction subflow blockaction merge double transform constseq bitfield coreaction condexe override dynamic crc32 prettyprint printlanguage printc printjava memstate opbehavior paramid signature sleigh_arch inject_sleigh";

    fn run(command: &mut Command) {
        let status = command.status().expect("launch native build command");
        assert!(status.success(), "native build command failed: {command:?}");
    }

    pub fn build() {
        println!("cargo:rerun-if-changed=native");
        println!("cargo:rerun-if-changed=src/lib.rs");
        println!("cargo:rerun-if-changed=../third_party/ghidra/cpp");
        println!("cargo:rerun-if-changed=../third_party/ghidra/specs");
        if env::var_os("CARGO_FEATURE_NATIVE").is_none() {
            return;
        }
        let host = env::var("HOST").unwrap();
        let target = env::var("TARGET").unwrap();
        assert!(host == target && (target.contains("linux") || target.contains("apple")),
        "native decompiler currently requires a native Linux or macOS build and zlib development headers");
        let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
        let source = PathBuf::from("../third_party/ghidra/cpp");
        let specs = PathBuf::from("../third_party/ghidra/specs");
        let mut compiler = cc::Build::new();
        compiler
            .cpp(true)
            .std("c++11")
            .opt_level(2)
            .warnings(false)
            .cargo_metadata(false)
            .include(&source);
        for name in format!("{CORE} {SLEIGH} slgh_compile slghparse slghscan").split_whitespace() {
            compiler.file(source.join(format!("{name}.cc")));
        }
        compiler.compile("sleigh_compiler");
        let executable = out.join("sleigh-compile");
        run(compiler
            .get_compiler()
            .to_command()
            .arg(out.join("libsleigh_compiler.a"))
            .arg("-lz")
            .arg("-o")
            .arg(&executable));
        let mut embedded = String::new();
        for (arch, slaspec, pspec, cspec) in [
            ("x64", "x86-64.slaspec", "x86-64.pspec", "x86-64-win.cspec"),
            ("x86", "x86.slaspec", "x86.pspec", "x86win.cspec"),
        ] {
            let sla = out.join(format!("{arch}.sla"));
            run(Command::new(&executable).arg(specs.join(slaspec)).arg(&sla));
            let pack = PathBuf::from(format!("data/winapi{}.pack", if arch == "x64" { "64" } else { "32" }));
            println!("cargo:rerun-if-changed={}", pack.display());
            for (name, path) in [
                ("sla", sla),
                ("pspec", specs.join(pspec)),
                ("cspec", specs.join(cspec)),
                ("pack", pack),
            ] {
                let bytes = fs::read(path).unwrap();
                embedded.push_str(&format!("static const unsigned char {name}_{arch}_bytes[] = {{"));
                for byte in bytes {
                    embedded.push_str(&format!("{byte},"));
                }
                embedded.push_str("};\n");
            }
        }
        fs::write(out.join("specs.hh"), embedded).unwrap();

        // Keep vendored sources byte-identical. Apply the documented integration
        // hooks only to build-directory copies, failing if the pinned text drifts.
        let mut native = cxx_build::bridge("src/lib.rs");
        native
            .cpp(true)
            .std("c++14")
            .opt_level(2)
            .warnings(false)
            .include(&source)
            .include("native")
            .include(&out)
            .file("native/bridge.cc");
        for name in format!("{CORE} {SLEIGH} {DECOMP}").split_whitespace() {
            let path = source.join(format!("{name}.cc"));
            let mut code = fs::read_to_string(&path).unwrap();
            let original = code.clone();
            if name == "sleigh" {
                replace(&mut code,
                "    ifstream s(el->getContent(), std::ios_base::binary);\n    if (!s)\n      throw LowlevelError(\"Could not open .sla file: \" + el->getContent());\n    decoder.ingestStream(s);\n    s.close();",
                "    std::istringstream s(capax_sla());\n    decoder.ingestStream(s);");
            }
            if name == "action" {
                replace(
                    &mut code,
                    "  do {\n    switch(status)",
                    "  do {\n    capax_check();\n    switch(status)",
                );
                replace(
                    &mut code,
                    "int4 ActionPool::processOp(PcodeOp *op,Funcdata &data)\n\n{",
                    "int4 ActionPool::processOp(PcodeOp *op,Funcdata &data)\n\n{\n  capax_check();",
                );
            }
            for (file, signature) in [
                (
                    "op",
                    "PcodeOp *PcodeOpBank::create(int4 inputs,const SeqNum &sq)",
                ),
                (
                    "varnode",
                    "Varnode *VarnodeBank::create(int4 s,const Address &m,Datatype *ct)",
                ),
                (
                    "sleigh",
                    "int4 Sleigh::oneInstruction(PcodeEmit &emit,const Address &baseaddr) const",
                ),
            ] {
                if name == file {
                    let needle = format!("{signature}\n\n{{");
                    replace(&mut code, &needle, &format!("{needle}\n  capax_check();"));
                }
            }
            if code != original {
                let patched = out.join(format!("{name}.cc"));
                fs::write(&patched, format!("#include \"hooks.hh\"\n{code}")).unwrap();
                native.file(patched);
            } else {
                native.file(path);
            }
        }
        native.compile("capa_ghidra");
        println!("cargo:rustc-link-lib=z");
    }
    fn replace(text: &mut String, from: &str, to: &str) {
        assert_eq!(
            text.matches(from).count(),
            1,
            "pinned Ghidra hook changed: {from}"
        );
        *text = text.replace(from, to);
    }
}
fn main() {
    #[cfg(feature = "native")]
    native::build();
}
