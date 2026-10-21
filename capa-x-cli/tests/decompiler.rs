use std::process::Command;
fn command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_capa-x"));
    command.arg(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../tests/decompiler/fixtures.dll"
    ));
    command
}
#[cfg(not(feature = "decompiler"))]
#[test]
fn disabled_backend_has_an_actionable_error() -> Result<(), Box<dyn std::error::Error>> {
    let output = command()
        .args(["--decompile-function", "0x140001000"])
        .output()?;
    assert!(!output.status.success());
    assert!(String::from_utf8(output.stderr)?.contains("rebuild with --features decompiler"));
    Ok(())
}
#[cfg(feature = "decompiler")]
#[test]
fn explicit_function_json_is_independent_of_jobs() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = include_bytes!("../../tests/decompiler/fixtures.dll");
    let image = capa_x::extract::image::LoadedImage::parse(bytes)?;
    // arithmetic is the fixture's first export, at RVA 0x1000.
    let address = format!("{:#x}", image.image_base + 0x1000);
    let mut outputs = Vec::new();
    for jobs in ["1", "4"] {
        let output = command()
            .args(["--decompile-function", &address, "--json", "--jobs", jobs])
            .output()?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let json: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        assert_eq!(
            json.get("name").and_then(|n| n.as_str()),
            Some("arithmetic")
        );
        assert!(json.get("timings").is_none());
        outputs.push(output.stdout);
    }
    assert_eq!(outputs.first(), outputs.get(1));
    let timed = command()
        .args(["--decompile-function", &address, "--json", "--timing"])
        .output()?;
    assert!(timed.status.success());
    let json: serde_json::Value = serde_json::from_slice(&timed.stdout)?;
    assert!(json.get("timings").is_some());
    Ok(())
}
#[test]
fn invalid_address_is_rejected_by_argument_parser() -> Result<(), Box<dyn std::error::Error>> {
    let output = command()
        .args(["--decompile-function", "not-hex"])
        .output()?;
    assert!(!output.status.success());
    assert!(String::from_utf8(output.stderr)?.contains("invalid hexadecimal function address"));
    Ok(())
}
