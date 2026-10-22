#![cfg(feature = "decompiler")]
use capa_x::decompiler::{DecompilerSession, ResourceLimits, ValueType};

const FIXTURE: &[u8] = include_bytes!("../../tests/decompiler/fixtures.dll");

#[test]
fn corpus_privilege_function_preserves_return_and_stack_arguments() -> anyhow::Result<()> {
    let sample = include_bytes!("../../tests/testfiles/071f2d1c4c2201ee95ffe2aa965000f5f615a11a12d345e33b9fb060e5597740.dll_");
    let mut session = DecompilerSession::from_pe(sample)?;
    let output = session.decompile_function(0x18000e450)?;
    println!("{}\n{:?}", output.text, output.warnings);
    assert!(!output.text.contains("void FUN_18000e450("));
    assert!(
        output.text.contains("return 1;") && output.text.contains("return 0;"),
        "{}",
        output.text
    );
    assert!(output.text.contains("SeDebugPrivilege"), "{}", output.text);
    assert!(output.text.contains("PrivilegeCount"), "{}", output.text);
    assert!(output.text.contains("Privileges[0]"), "{}", output.text);
    let compact: String = output.text.chars().filter(|c| !c.is_whitespace()).collect();
    let call = compact
        .split("advapi32_AdjustTokenPrivileges(")
        .nth(1)
        .and_then(|tail| tail.split(");").next())
        .ok_or_else(|| anyhow::anyhow!("missing privilege call"))?;
    assert_eq!(call.split(',').count(), 6, "{call}");
    assert!(!output
        .warnings
        .iter()
        .any(|warning| warning.contains("Unknown callee")));
    assert_eq!(session.decompile_function(0x18000e450)?.text, output.text);
    Ok(())
}

#[test]
fn explicitly_selected_unrecovered_wrapper_keeps_its_boundary() -> anyhow::Result<()> {
    let sample = include_bytes!("../../tests/testfiles/03b236b23b1ec37c663527c1f53af3fe.dll_");
    let mut analysis = capa_x::extract::recovery::analyze_with_backend(
        sample,
        capa_x::extract::recovery::RecoveryBackend::Native,
    )?;
    // Native recovery now finds the wrapper (a tail-jump target after padding).
    // The request path must still cope when a caller supplies an analysis that
    // lacks it, so drop it to keep exercising the unrecovered case.
    assert!(analysis.functions.remove(&0x180051ad0).is_some());
    assert!(analysis.functions.contains_key(&0x18001e610));
    let mut session =
        DecompilerSession::from_analysis(&analysis, &Default::default(), Default::default())?;
    let output = session.decompile_function(0x180051ad0)?;
    println!("{}\n{:?}", output.text, output.warnings);
    assert!(output.text.contains("FUN_18001e610("), "{}", output.text);
    assert!(!output.warnings.iter().any(|w| w.contains("jumptable")));
    assert!(output.text.len() < 400, "{}", output.text);
    session.decompile_function(0x18001e610)?;
    assert_eq!(session.decompile_function(0x180051ad0)?.text, output.text);
    Ok(())
}
#[test]
fn native_recovery_finds_a_tail_jump_wrapper() -> anyhow::Result<()> {
    let sample = include_bytes!("../../tests/testfiles/03b236b23b1ec37c663527c1f53af3fe.dll_");
    let analysis = capa_x::extract::recovery::analyze_with_backend(
        sample,
        capa_x::extract::recovery::RecoveryBackend::Native,
    )?;
    // Flow folds the wrapper into the function that jumps to it. Only native
    // recovery treats a tail-jump target after padding as a function start.
    assert!(analysis.functions.contains_key(&0x180051ad0));
    let compat = capa_x::extract::recovery::analyze_with_backend(
        sample,
        capa_x::extract::recovery::RecoveryBackend::VivisectCompat,
    )?;
    assert!(!compat.functions.contains_key(&0x180051ad0));
    Ok(())
}
fn address(name: &str) -> anyhow::Result<u64> {
    let pe = goblin::pe::PE::parse(FIXTURE)?;
    let export = pe
        .exports
        .iter()
        .find(|e| e.name == Some(name))
        .ok_or_else(|| anyhow::anyhow!("missing export {name}"))?;
    Ok(pe.image_base + export.rva as u64)
}
fn supply_source_signatures(session: &mut DecompilerSession) -> anyhow::Result<()> {
    use ValueType as T;
    for (name, result, parameters) in [
        ("arithmetic", T::I32, vec![T::I32, T::I32]),
        ("branches", T::I32, vec![T::I32]),
        ("loops", T::I32, vec![T::I32]),
        ("switches", T::I32, vec![T::I32, T::I32]),
        ("stack_variables", T::I32, vec![T::I32]),
        ("imported_call", T::U32, vec![T::U32]),
        ("nonreturn", T::Void, vec![T::U32]),
    ] {
        session.set_signature(address(name)?, result, &parameters)?;
    }
    let image = capa_x::extract::image::LoadedImage::parse(FIXTURE)?;
    for (slot, name) in &image.import_locations {
        if name.ends_with(".GetTickCount") {
            session.set_signature(*slot, T::U32, &[])?;
        }
        if name.ends_with(".ExitProcess") {
            session.set_signature(*slot, T::Void, &[T::U32])?;
        }
    }
    Ok(())
}
#[test]
fn source_logic_and_reuse() -> anyhow::Result<()> {
    let mut session = DecompilerSession::from_pe(FIXTURE)?;
    supply_source_signatures(&mut session)?;
    let mut texts = Vec::new();
    for name in [
        "arithmetic",
        "branches",
        "loops",
        "switches",
        "stack_variables",
        "imported_call",
        "nonreturn",
    ] {
        let output = session.decompile_function(address(name)?)?;
        println!("{name}: {}\n{:?}", output.text, output.warnings);
        assert_eq!(output.name.as_deref(), Some(name));
        assert!(output.text.contains(name));
        assert!(!output.text.trim().is_empty());
        if name == "nonreturn" {
            assert!(output
                .warnings
                .iter()
                .any(|w| w.contains("Subroutine does not return")));
        } else {
            assert!(!output.incomplete, "{name}: {:?}", output.warnings);
        }
        texts.push((name, output.text));
    }
    for (name, text) in &texts {
        assert_eq!(&session.decompile_function(address(name)?)?.text, text);
    }
    let get = |name| {
        texts
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, text)| text.as_str())
            .unwrap_or("")
    };
    assert!(get("arithmetic").contains("* 7"));
    assert!(get("branches").contains("if ("));
    assert!(get("loops").contains("while (") || get("loops").contains("for ("));
    assert!(get("switches").contains("switch(") || get("switches").contains("switch ("));
    assert!(get("stack_variables").contains("[param_1 & 1]"));
    assert!(get("stack_variables").contains("param_1 + 9"));
    assert!(get("imported_call").contains("GetTickCount"));
    assert!(get("nonreturn").contains("void nonreturn(uint4 param_1)"));
    assert!(get("nonreturn").contains("ExitProcess(param_1)"));
    assert!(get("switches").contains("branches(param_2)"));
    assert!(get("switches").contains("loops(param_2)"));
    Ok(())
}
#[test]
fn unsupported_and_invalid_requests_are_controlled() -> anyhow::Result<()> {
    assert!(DecompilerSession::from_pe(b"not a PE").is_err());
    let nt = u32::from_le_bytes(
        FIXTURE
            .get(0x3c..0x40)
            .ok_or_else(|| anyhow::anyhow!("missing PE offset"))?
            .try_into()?,
    ) as usize;
    for machine in [0x014cu16, 0xaa64u16] {
        let mut other_architecture = FIXTURE.to_vec();
        other_architecture
            .get_mut(nt + 4..nt + 6)
            .ok_or_else(|| anyhow::anyhow!("missing machine field"))?
            .copy_from_slice(&machine.to_le_bytes());
        assert!(matches!(
            DecompilerSession::from_pe(&other_architecture),
            Err(capa_x::decompiler::DecompileError::Unsupported(_))
        ));
    }
    for length in [0, 2, 64, 256, 512] {
        assert!(DecompilerSession::from_pe(FIXTURE.get(..length).unwrap_or_default()).is_err());
    }
    let mut session = DecompilerSession::from_pe(FIXTURE)?;
    assert!(session.decompile_function(0).is_err());
    assert!(session.decompile_function(u64::MAX).is_err());
    assert!(session
        .set_limits(ResourceLimits {
            timeout_ms: 0,
            ..Default::default()
        })
        .is_err());
    assert!(!session
        .decompile_function(address("arithmetic")?)?
        .text
        .is_empty());
    Ok(())
}
#[test]
fn work_limit_is_an_error_and_leaves_the_session_usable() -> anyhow::Result<()> {
    let mut session = DecompilerSession::from_pe(FIXTURE)?;
    let expected = DecompilerSession::from_pe(FIXTURE)?
        .decompile_function(address("switches")?)?
        .text;
    session.set_limits(ResourceLimits {
        max_work: 1,
        ..Default::default()
    })?;
    let error = session
        .decompile_function(address("loops")?)
        .err()
        .ok_or_else(|| anyhow::anyhow!("expected work limit error"))?;
    assert!(error.to_string().contains("work limit"), "{error}");
    // A cooperative limit aborts one request and nothing else.
    session.set_limits(ResourceLimits::default())?;
    assert_eq!(
        session.decompile_function(address("switches")?)?.text,
        expected
    );
    Ok(())
}

#[test]
fn enrichment_budget_is_separate_and_its_failure_keeps_the_function() -> anyhow::Result<()> {
    let target = address("switches")?;
    let plain = DecompilerSession::from_pe(FIXTURE)?.decompile_function(target)?;
    // Find a budget large enough for the selected function alone but too small
    // for callee inference to finish within its own, equal budget.
    let mut found = false;
    for max_work in [200, 400, 800, 1_600, 3_200, 6_400, 12_800, 25_600] {
        let mut session = DecompilerSession::from_pe(FIXTURE)?;
        session.set_limits(ResourceLimits {
            max_work,
            ..Default::default()
        })?;
        let Ok(output) = session.decompile_function(target) else {
            continue;
        };
        if output
            .warnings
            .iter()
            .any(|w| w.contains("inference skipped"))
        {
            assert!(output.incomplete);
            assert!(output.text.contains("switches("), "{}", output.text);
            // The session survives and still produces the full result.
            session.set_limits(ResourceLimits::default())?;
            assert_eq!(session.decompile_function(target)?.text, plain.text);
            found = true;
            break;
        }
    }
    assert!(found, "no budget exercised the skipped-enrichment path");
    Ok(())
}

#[test]
fn output_does_not_depend_on_request_order() -> anyhow::Result<()> {
    let names = [
        "switches",
        "branches",
        "loops",
        "arithmetic",
        "imported_call",
        "nonreturn",
    ];
    let mut reference = Vec::new();
    for name in names {
        let mut fresh = DecompilerSession::from_pe(FIXTURE)?;
        reference.push(fresh.decompile_function(address(name)?)?.text);
    }
    // Deterministic shuffles of the same requests on a single session.
    for rotation in 0..names.len() {
        for reversed in [false, true] {
            let mut order: Vec<usize> = (0..names.len()).map(|i| (i + rotation) % names.len()).collect();
            if reversed {
                order.reverse();
            }
            let mut session = DecompilerSession::from_pe(FIXTURE)?;
            for index in order {
                assert_eq!(
                    session.decompile_function(address(names[index])?)?.text,
                    reference[index],
                    "{} after rotation {rotation} reversed={reversed}",
                    names[index]
                );
            }
        }
    }
    Ok(())
}

#[test]
fn malformed_import_directory_loads_without_imports() -> anyhow::Result<()> {
    let mut bytes = FIXTURE.to_vec();
    let pe = goblin::pe::PE::parse(&bytes)?;
    // Delay import data directory (index 13) claiming millions of descriptors.
    let entry = pe.header.dos_header.pe_pointer as usize + 4 + 20 + 112 + 13 * 8;
    bytes[entry..entry + 4].copy_from_slice(&0x6000u32.to_le_bytes());
    bytes[entry + 4..entry + 8].copy_from_slice(&0x7fff_fff0u32.to_le_bytes());
    assert!(DecompilerSession::from_pe(FIXTURE).is_ok());
    let mut session = DecompilerSession::from_pe(&bytes)?;
    let output = session.decompile_function(address("arithmetic")?)?;
    assert!(output.text.contains("arithmetic"), "{}", output.text);
    assert!(output.warnings.iter().any(|w| w.contains("import directory ignored")), "{:?}", output.warnings);
    assert!(output.incomplete);
    Ok(())
}

#[test]
fn interleaved_sessions_keep_their_own_translator() -> anyhow::Result<()> {
    let mut first = DecompilerSession::from_pe(FIXTURE)?;
    let mut second = DecompilerSession::from_pe(FIXTURE)?;
    let entry = address("arithmetic")?;
    let text = first.decompile_function(entry)?.text;
    assert_eq!(second.decompile_function(entry)?.text, text);
    drop(second);
    assert_eq!(first.decompile_function(entry)?.text, text);
    Ok(())
}

#[test]
fn unknown_prototypes_are_explicitly_incomplete() -> anyhow::Result<()> {
    let mut analysis = capa_x::extract::recovery::analyze_with_backend(
        FIXTURE,
        capa_x::extract::recovery::RecoveryBackend::Native,
    )?;
    // An unrelated DLL's same-named API must not inherit a Windows prototype.
    for name in analysis.image.import_locations.values_mut() {
        *name = name.replace("kernel32.", "custom.");
    }
    let mut session =
        DecompilerSession::from_analysis(&analysis, &Default::default(), Default::default())?;
    let output = session.decompile_function(address("imported_call")?)?;
    assert!(output.incomplete);
    assert!(output.unknown_callees);
    assert!(output
        .warnings
        .iter()
        .any(|w| w.contains("Unknown callee prototype")));
    assert!(session
        .set_signature(address("arithmetic")?, ValueType::I32, &[ValueType::Void])
        .is_err());
    Ok(())
}

#[test]
fn automatic_context_and_request_order() -> anyhow::Result<()> {
    let mut session = DecompilerSession::from_pe(FIXTURE)?;
    let switch = session.decompile_function(address("switches")?)?;
    assert!(switch.text.contains("branches(param_2)"), "{}", switch.text);
    assert!(switch.text.contains("loops(param_2)"), "{}", switch.text);
    assert!(switch.text.contains("int4 switches("));
    assert!(!switch.warnings.iter().any(|w| w.contains("Unknown callee")));
    assert!(switch
        .warnings
        .iter()
        .any(|w| w.contains("prototypes inferred")));
    assert!(session
        .decompile_function(address("nonreturn")?)?
        .text
        .contains("ExitProcess(param_1)"));
    assert!(
        !session
            .decompile_function(address("imported_call")?)?
            .incomplete
    );
    // Support analysis does not permanently lock the functions it visits.
    session.decompile_function(address("branches")?)?;
    assert_eq!(
        session.decompile_function(address("switches")?)?.text,
        switch.text
    );
    session.set_signature(address("branches")?, ValueType::U32, &[ValueType::U32])?;
    let changed = session.decompile_function(address("switches")?)?.text;
    let mut fresh = DecompilerSession::from_pe(FIXTURE)?;
    fresh.set_signature(address("branches")?, ValueType::U32, &[ValueType::U32])?;
    assert_eq!(
        changed,
        fresh.decompile_function(address("switches")?)?.text
    );
    Ok(())
}

#[test]
fn real_dll_entry_preserves_runtime_tail_call() -> anyhow::Result<()> {
    let sample = include_bytes!("../../tests/testfiles/03b236b23b1ec37c663527c1f53af3fe.dll_");
    let mut session = DecompilerSession::from_pe(sample)?;
    let output = session.decompile_function(0x180034818)?;
    println!("{}\n{:?}", output.text, output.warnings);
    assert!(
        output.text.contains("__security_init_cookie()"),
        "{}",
        output.text
    );
    assert!(
        output
            .text
            .contains("__DllMainCRTStartup(param_1,param_2,param_3)"),
        "{}",
        output.text
    );
    assert!(!output.text.contains("param_4"));
    assert!(!output.warnings.iter().any(|w| w.contains("Unknown callee")));
    assert_eq!(session.decompile_function(0x180034818)?.text, output.text);
    Ok(())
}

#[test]
fn function_id_names_and_types_a_static_runtime_function() -> anyhow::Result<()> {
    let sample = include_bytes!("../../tests/testfiles/92d8ea10ea30e8b534334a1c9857a455.exe_");
    let mut session = DecompilerSession::from_pe(sample)?;
    let output = session.decompile_function(0x1400aa420)?;
    assert!(
        output
            .text
            .trim_start()
            .starts_with("void * __cdecl memset(void *_Dst,int _Val,size_t _Size)"),
        "{}",
        output.text
    );
    assert!(!output.text.contains("FUN_1400aa420"), "{}", output.text);
    assert_eq!(session.decompile_function(0x1400aa420)?.text, output.text);
    Ok(())
}

#[test]
fn stack_probe_and_cookie_helpers_use_their_modeled_effects() -> anyhow::Result<()> {
    let sample = include_bytes!("../../tests/testfiles/10ebcf8c20403457a08762200015b151.exe_");
    let mut session = DecompilerSession::from_pe(sample)?;
    // A large frame: `__chkstk` must not leave the stack pointer unknown, which
    // used to turn every local into an `stack0x...` address.
    let output = session.decompile_function(0x140006954)?;
    for expected in [
        "replaced with injection: alloca_probe",
        "replaced with injection: security_check_cookie",
    ] {
        assert!(
            output.text.contains(expected),
            "{expected}\n{}",
            output.text
        );
    }
    assert!(!output.text.contains("stack0x"), "{}", output.text);
    assert!(!output.text.contains("__chkstk()"), "{}", output.text);
    assert!(
        !output.text.contains("__security_check_cookie("),
        "{}",
        output.text
    );
    assert_eq!(session.decompile_function(0x140006954)?.text, output.text);

    // A cookie check is only a modeled effect: the handler below has nothing else
    // to report, and the dead cookie computation no longer shapes its parameters.
    let sample = include_bytes!("../../tests/testfiles/6cd1315f6f2fa4f8ee2b98bb3ca0a994.exe_");
    let mut session = DecompilerSession::from_pe(sample)?;
    let output = session.decompile_function(0x1400018f0)?;
    assert!(
        !output.text.contains("__security_check_cookie("),
        "{}",
        output.text
    );
    assert!(!output.incomplete, "{:?}", output.warnings);
    Ok(())
}
