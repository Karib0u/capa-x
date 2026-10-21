#![cfg(feature = "native")]
use capa_x_ghidra::Session;

#[test]
fn explicit_register_effect_preserves_return_without_changing_ordinary_calls(
) -> Result<(), Box<dyn std::error::Error>> {
    use capa_x_ghidra::ValueType;
    // mov eax,42; call helper; ret; padding; ret
    let mut bytes = vec![0xb8, 42, 0, 0, 0, 0xe8, 6, 0, 0, 0, 0xc3];
    bytes.resize(16, 0x90);
    bytes.push(0xc3);
    let mut session = Session::new()?;
    session.add_section(0x1000, &bytes, true, true)?;
    session.add_function(0x1000, "caller", false)?;
    session.add_function(0x1010, "helper", false)?;
    session.set_signature(0x1010, ValueType::Void, &[])?;
    let ordinary = session.decompile(0x1000, 5000, 1000, 100_000)?;
    assert!(!ordinary.text.contains("return 0x2a"), "{}", ordinary.text);
    assert!(session.set_preserves_rax(0).is_err());
    session.set_preserves_rax(0x1010)?;
    let preserved = session.decompile(0x1000, 5000, 1000, 100_000)?;
    assert!(preserved.text.contains("return 0x2a"), "{}", preserved.text);
    assert_eq!(
        session.decompile(0x1000, 5000, 1000, 100_000)?.text,
        preserved.text
    );
    Ok(())
}

#[test]
fn deadline_is_checked_during_translation() -> Result<(), Box<dyn std::error::Error>> {
    let mut session = Session::new()?;
    let mut bytes = vec![0x90; 60_000];
    bytes.push(0xc3);
    session.add_section(0x1000, &bytes, true, true)?;
    session.add_function(0x1000, "long_function", false)?;
    let started = std::time::Instant::now();
    let error = session
        .decompile(0x1000, 1, 100_000, 10_000_000)
        .err()
        .ok_or("expected deadline error")?;
    assert!(error.to_string().contains("deadline"), "{error}");
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
    Ok(())
}

#[test]
fn image_validation_and_instruction_limits() -> Result<(), Box<dyn std::error::Error>> {
    let mut session = Session::new()?;
    assert!(session.add_section(u64::MAX, &[0xc3], true, true).is_err());
    assert!(session.add_section(0x1000, &[], true, true).is_err());
    session.add_section(0x1000, &[0x90, 0x90, 0x90, 0xc3], true, true)?;
    assert!(session.add_section(0x1001, &[0xc3], true, true).is_err());
    assert!(session
        .add_function(0x1000, &"x".repeat(1025), false)
        .is_err());
    session.add_function(0x1000, "bounded_function", false)?;
    match session.decompile(0x1000, 5000, 1, 100_000) {
        Err(error) => assert!(
            error.to_string().to_lowercase().contains("instruction"),
            "{error}"
        ),
        Ok(output) => assert!(output.incomplete),
    }
    Ok(())
}

#[test]
fn malformed_code_is_a_result_not_a_crash() -> Result<(), Box<dyn std::error::Error>> {
    for bytes in [
        &[0x0f][..],
        &[0xff, 0xff][..],
        &[0xe9, 0xff, 0xff, 0xff, 0x7f][..],
    ] {
        let mut session = Session::new()?;
        session.add_section(0x1000, bytes, true, true)?;
        session.add_function(0x1000, "malformed", false)?;
        if let Ok(output) = session.decompile(0x1000, 100, 1000, 10_000) {
            assert!(output.incomplete, "{}", output.text);
        }
    }
    Ok(())
}

#[test]
fn sessions_created_on_separate_threads_are_serialized() -> Result<(), Box<dyn std::error::Error>> {
    let handles: Vec<_> = (0..4)
        .map(|_| {
            std::thread::spawn(|| -> Result<String, String> {
                let run = || -> Result<String, capa_x_ghidra::Error> {
                    let mut session = Session::new()?;
                    session.add_section(0x1000, &[0x8d, 0x41, 0x01, 0xc3], true, true)?;
                    session.add_function(0x1000, "increment", false)?;
                    Ok(session.decompile(0x1000, 5000, 1000, 100_000)?.text)
                };
                run().map_err(|e| e.to_string())
            })
        })
        .collect();
    let mut outputs = Vec::new();
    for handle in handles {
        outputs.push(handle.join().map_err(|_| "thread panicked")??);
    }
    assert!(outputs.windows(2).all(|pair| pair.first() == pair.get(1)));
    Ok(())
}

#[test]
fn tail_calls_and_recursive_callees_are_bounded() -> Result<(), Box<dyn std::error::Error>> {
    let mut session = Session::new()?;
    // jmp 0x1010; padding; lea eax,[rcx+1]; ret
    let mut bytes = vec![0xe9, 0x0b, 0, 0, 0];
    bytes.resize(16, 0x90);
    bytes.extend_from_slice(&[0x8d, 0x41, 1, 0xc3]);
    session.add_section(0x1000, &bytes, true, true)?;
    session.add_function(0x1000, "wrapper", false)?;
    session.add_function(0x1010, "increment", false)?;
    assert!(session.add_tail_call(0, 0x1000, 0x1010).is_err());
    assert!(session.add_tail_call(0x1000, 0x1000, 0).is_err());
    session.add_tail_call(0x1000, 0x1000, 0x1010)?;
    let first = session.decompile(0x1000, 5000, 1000, 100_000)?;
    assert!(first.text.contains("increment(param_1)"), "{}", first.text);
    assert!(!first.text.contains("+ 1"));
    assert_eq!(
        session.decompile(0x1000, 5000, 1000, 100_000)?.text,
        first.text
    );

    let mut recursive = Session::new()?;
    // caller calls recursive; recursive calls itself.
    let mut bytes = vec![0xe8, 0x0b, 0, 0, 0, 0xc3];
    bytes.resize(16, 0x90);
    bytes.extend_from_slice(&[0xe8, 0xfb, 0xff, 0xff, 0xff, 0xc3]);
    recursive.add_section(0x1000, &bytes, true, true)?;
    recursive.add_function(0x1000, "caller", false)?;
    recursive.add_function(0x1010, "recursive", false)?;
    let output = recursive.decompile(0x1000, 5000, 1000, 100_000)?;
    assert!(output.incomplete);
    assert!(output.warnings.iter().any(|w| w.contains("Unknown callee")));
    Ok(())
}

#[test]
fn import_jump_thunk_preserves_forwarded_argument() -> Result<(), Box<dyn std::error::Error>> {
    use capa_x_ghidra::ValueType;
    let mut session = Session::new()?;
    // jmp qword ptr [rip+0xffa], through the IAT slot at 0x2000.
    session.add_section(0x1000, &[0xff, 0x25, 0xfa, 0x0f, 0, 0], true, true)?;
    session.add_section(0x2000, &[0; 8], false, false)?;
    session.add_function(0x1000, "exit_thunk", false)?;
    session.add_import(0x2000, "ExitProcess", true)?;
    session.set_signature(0x2000, ValueType::Void, &[ValueType::U32])?;
    session.add_tail_call(0x1000, 0x1000, 0x2000)?;
    let output = session.decompile(0x1000, 5000, 1000, 100_000)?;
    assert!(
        output.text.contains("ExitProcess(param_1)"),
        "{}",
        output.text
    );
    Ok(())
}
