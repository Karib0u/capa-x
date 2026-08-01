#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fmt::Write as _;
use std::path::Path;
use std::process::Command;

use capa_x::extract::recovery::analyze;

#[test]
fn custom_signature_populates_metadata_and_skips_the_function() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let sample = root.join("tests/testfiles/Practical Malware Analysis Lab 01-01.exe_");
    let bytes = std::fs::read(&sample).expect("pinned PE sample exists");
    let analysis = analyze(&bytes).expect("sample recovery succeeds");
    let (&address, _) = analysis
        .functions
        .iter()
        .find(|(address, _)| {
            analysis
                .image
                .bytes_at(**address, 32)
                .is_some_and(|bytes| bytes.len() == 32)
        })
        .expect("sample has a 32-byte file-backed function");
    let function_bytes = analysis
        .image
        .bytes_at(address, 32)
        .expect("selected function bytes remain available");
    let mut pattern = String::new();
    for byte in function_bytes {
        write!(pattern, "{byte:02X}").expect("writing to String is infallible");
    }

    let temporary = std::env::temp_dir().join(format!("capa-x-flirt-cli-{}", std::process::id()));
    std::fs::create_dir_all(&temporary).expect("temporary directory is writable");
    let signature = temporary.join("test.pat");
    std::fs::write(
        &signature,
        format!("{pattern} 00 0000 0020 :0000 __m5_cli_library\n---"),
    )
    .expect("temporary signature is writable");

    let output = Command::new(env!("CARGO_BIN_EXE_capa-x"))
        .arg(&sample)
        .arg("--rules")
        .arg(root.join("capa-x/tests/fixtures/rules/flirt"))
        .arg("--signatures")
        .arg(&signature)
        .arg("--json")
        .output()
        .expect("CLI starts");
    let _ = std::fs::remove_dir_all(&temporary);
    assert!(
        output.status.success(),
        "CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let document: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("CLI emits JSON");
    let libraries = document["meta"]["analysis"]["library_functions"]
        .as_array()
        .expect("library function metadata is an array");
    assert!(libraries.iter().any(|library| {
        library["address"]["value"].as_u64() == Some(address)
            && library["name"].as_str() == Some("__m5_cli_library")
    }));
    let analyzed_count = document["meta"]["analysis"]["feature_counts"]["functions"]
        .as_array()
        .expect("function feature counts are an array")
        .len();
    assert_eq!(analyzed_count, analysis.functions.len() - libraries.len());
}
