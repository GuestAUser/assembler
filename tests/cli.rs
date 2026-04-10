use assert_cmd::Command;
use object::write::{Object as WriteObject, Symbol, SymbolSection as WriteSymbolSection};
use object::{
    Architecture as ObjectArchitecture, BinaryFormat, Endianness, SectionKind, SymbolFlags,
    SymbolKind, SymbolScope,
};
use predicates::prelude::*;
use serde_json::Value;
use std::{
    fs,
    path::Path,
    process,
    time::{SystemTime, UNIX_EPOCH},
};

fn unique_temp_path(label: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("assembler-{label}-{}-{nanos}", process::id()))
}

fn escaped_display_path(path: &Path) -> String {
    path.display()
        .to_string()
        .chars()
        .flat_map(|character| character.escape_default())
        .collect()
}

fn write_test_object(path: &std::path::Path) {
    let mut object = WriteObject::new(
        BinaryFormat::Elf,
        ObjectArchitecture::X86_64,
        Endianness::Little,
    );
    object.add_file_symbol(b"fixture.o".to_vec());

    let text_section = object.add_section(Vec::new(), b".text".to_vec(), SectionKind::Text);
    let init_section = object.add_section(Vec::new(), b".init".to_vec(), SectionKind::Text);

    let entry_offset =
        object.append_section_data(text_section, &[0x55, 0x48, 0x89, 0xe5, 0x5d, 0xc3], 1);
    let init_offset = object.append_section_data(init_section, &[0x90, 0xc3], 1);

    object.add_symbol(Symbol {
        name: b"entry".to_vec(),
        value: entry_offset,
        size: 6,
        kind: SymbolKind::Text,
        scope: SymbolScope::Linkage,
        weak: false,
        section: WriteSymbolSection::Section(text_section),
        flags: SymbolFlags::None,
    });
    object.add_symbol(Symbol {
        name: b"init_func".to_vec(),
        value: init_offset,
        size: 2,
        kind: SymbolKind::Text,
        scope: SymbolScope::Linkage,
        weak: false,
        section: WriteSymbolSection::Section(init_section),
        flags: SymbolFlags::None,
    });

    fs::write(path, object.write().unwrap()).unwrap();
}

fn write_thumb_test_object(path: &std::path::Path) {
    let mut object = WriteObject::new(
        BinaryFormat::Elf,
        ObjectArchitecture::Arm,
        Endianness::Little,
    );
    object.add_file_symbol(b"thumb-fixture.o".to_vec());

    let text_section = object.add_section(Vec::new(), b".text".to_vec(), SectionKind::Text);
    let entry_offset = object.append_section_data(text_section, &[0x00, 0xbf], 1);

    object.add_symbol(Symbol {
        name: b"thumb_entry".to_vec(),
        value: entry_offset,
        size: 2,
        kind: SymbolKind::Text,
        scope: SymbolScope::Linkage,
        weak: false,
        section: WriteSymbolSection::Section(text_section),
        flags: SymbolFlags::None,
    });

    fs::write(path, object.write().unwrap()).unwrap();
}

fn write_thumb_lsb_symbol_test_object(path: &std::path::Path) {
    let mut object = WriteObject::new(
        BinaryFormat::Elf,
        ObjectArchitecture::Arm,
        Endianness::Little,
    );
    object.add_file_symbol(b"thumb-lsb-fixture.o".to_vec());

    let text_section = object.add_section(Vec::new(), b".text".to_vec(), SectionKind::Text);
    let entry_offset = object.append_section_data(text_section, &[0x00, 0xbf], 1);

    object.add_symbol(Symbol {
        name: b"thumb_entry".to_vec(),
        value: entry_offset + 1,
        size: 2,
        kind: SymbolKind::Text,
        scope: SymbolScope::Linkage,
        weak: false,
        section: WriteSymbolSection::Section(text_section),
        flags: SymbolFlags::None,
    });

    fs::write(path, object.write().unwrap()).unwrap();
}

fn write_big_endian_aarch64_test_object(path: &std::path::Path) {
    let mut object = WriteObject::new(
        BinaryFormat::Elf,
        ObjectArchitecture::Aarch64,
        Endianness::Big,
    );
    object.add_file_symbol(b"big-endian-aarch64.o".to_vec());

    let text_section = object.add_section(Vec::new(), b".text".to_vec(), SectionKind::Text);
    let entry_offset = object.append_section_data(text_section, &[0xc0, 0x03, 0x5f, 0xd6], 1);

    object.add_symbol(Symbol {
        name: b"entry".to_vec(),
        value: entry_offset,
        size: 4,
        kind: SymbolKind::Text,
        scope: SymbolScope::Linkage,
        weak: false,
        section: WriteSymbolSection::Section(text_section),
        flags: SymbolFlags::None,
    });

    fs::write(path, object.write().unwrap()).unwrap();
}

#[test]
fn cli_disassembles_raw_x86_64_bytes() {
    let mut command = Command::cargo_bin("assembler").unwrap();
    command
        .args(["--raw-hex", "55 48 89 e5 5d c3", "--arch", "x86-64"])
        .assert()
        .success()
        .stdout(predicate::str::contains("push"))
        .stdout(predicate::str::contains("mov"))
        .stdout(predicate::str::contains("ret"));
}

#[test]
fn cli_analysis_reports_no_supported_finding_for_simple_raw_function() {
    let mut command = Command::cargo_bin("assembler").unwrap();
    command
        .args([
            "--raw-hex",
            "55 48 89 e5 5d c3",
            "--arch",
            "x86-64",
            "--analyze",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("analysis     : enabled"))
        .stdout(predicate::str::contains(
            "No supported memory-safety findings were identified",
        ));
}

#[test]
fn cli_analysis_reports_stack_write_loop_findings_for_risky_raw_sample() {
    let mut command = Command::cargo_bin("assembler").unwrap();
    command
        .args([
            "--raw-hex",
            "55 48 89 e5 48 83 ec 20 31 c0 c6 44 05 f0 41 48 83 c0 01 48 83 f8 40 75 f1 c9 c3",
            "--arch",
            "x86-64",
            "--analyze",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "potential-stack-buffer-write-risk",
        ))
        .stdout(predicate::str::contains(
            "possible-out-of-bounds-local-write",
        ))
        .stdout(predicate::str::contains("suspicious-copy-loop"));
}

#[test]
fn cli_supports_att_syntax_for_x86_64() {
    let mut command = Command::cargo_bin("assembler").unwrap();
    command
        .args([
            "--raw-hex",
            "55 48 89 e5 5d c3",
            "--arch",
            "x86-64",
            "--syntax",
            "att",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("pushq"))
        .stdout(predicate::str::contains("%rbp"))
        .stdout(predicate::str::contains("retq"));
}

#[test]
fn cli_applies_base_address_to_raw_output() {
    let mut command = Command::cargo_bin("assembler").unwrap();
    command
        .args([
            "--raw-hex",
            "c3",
            "--arch",
            "x86-64",
            "--base-address",
            "0x401000",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("0x0000000000401000"));
}

#[test]
fn cli_disassembles_aarch64_raw_bytes() {
    let mut command = Command::cargo_bin("assembler").unwrap();
    command
        .args(["--raw-hex", "c0 03 5f d6", "--arch", "aarch64"])
        .assert()
        .success()
        .stdout(predicate::str::contains("ret"));
}

#[test]
fn cli_omits_syntax_metadata_for_aarch64_raw_bytes() {
    let mut command = Command::cargo_bin("assembler").unwrap();
    command
        .args(["--raw-hex", "c0 03 5f d6", "--arch", "aarch64"])
        .assert()
        .success()
        .stdout(predicate::str::contains("architecture: aarch64"))
        .stdout(predicate::str::contains("syntax").not());
}

#[test]
fn cli_defaults_to_plain_output_when_captured() {
    let mut command = Command::cargo_bin("assembler").unwrap();
    command
        .args(["--raw-hex", "c3", "--arch", "x86-64"])
        .assert()
        .success()
        .stdout(predicate::str::contains("target       : <raw-hex>"))
        .stdout(predicate::str::contains("ret"))
        .stdout(predicate::str::contains("╭─ DISASSEMBLY").not())
        .stdout(predicate::str::contains("\u{1b}[").not());
}

#[test]
fn cli_can_force_color_output_for_plain_render() {
    let mut command = Command::cargo_bin("assembler").unwrap();
    command
        .args([
            "--raw-hex",
            "c3",
            "--arch",
            "x86-64",
            "--render",
            "plain",
            "--color",
            "always",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("target"))
        .stdout(predicate::str::contains("ret"))
        .stdout(predicate::str::contains("╭─ DISASSEMBLY").not())
        .stdout(predicate::str::contains("\u{1b}["));
}

#[test]
fn cli_rejects_raw_disassembly_without_architecture() {
    let mut command = Command::cargo_bin("assembler").unwrap();
    command
        .args(["--raw-hex", "c3"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--arch is required"));
}

#[test]
fn cli_can_force_pretty_output_without_color() {
    let mut command = Command::cargo_bin("assembler").unwrap();
    command
        .args([
            "--raw-hex",
            "c3",
            "--arch",
            "x86-64",
            "--render",
            "pretty",
            "--color",
            "never",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("╭─ DISASSEMBLY"))
        .stdout(predicate::str::contains("ret"))
        .stdout(predicate::str::contains("\u{1b}[").not());
}

#[test]
fn cli_can_force_color_output_for_pretty_render() {
    let mut command = Command::cargo_bin("assembler").unwrap();
    command
        .args([
            "--raw-hex",
            "c3",
            "--arch",
            "x86-64",
            "--render",
            "pretty",
            "--color",
            "always",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("╭─ "))
        .stdout(predicate::str::contains("DISASSEMBLY"))
        .stdout(predicate::str::contains("\u{1b}["));
}

#[test]
fn cli_escapes_hostile_file_paths_in_errors() {
    let path = unique_temp_path("bad-name.bin");
    fs::write(&path, b"definitely not an object file").unwrap();

    let mut command = Command::cargo_bin("assembler").unwrap();
    command
        .arg(&path)
        .assert()
        .failure()
        .stderr(predicate::str::contains("failed to parse executable"))
        .stderr(predicate::str::contains(escaped_display_path(&path)));

    fs::remove_file(path).unwrap();
}

#[test]
fn cli_rejects_oversized_raw_hex_input() {
    let oversized = "aa".repeat((8 * 1024) + 1);

    let mut command = Command::cargo_bin("assembler").unwrap();
    command
        .args(["--raw-hex", oversized.as_str(), "--arch", "x86-64"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "raw hex input exceeds maximum supported size",
        ));
}

#[test]
fn cli_disassembles_object_file_with_labels_and_metadata() {
    let path = unique_temp_path("fixture.o");
    write_test_object(&path);

    let mut command = Command::cargo_bin("assembler").unwrap();
    command
        .arg(&path)
        .assert()
        .success()
        .stdout(predicate::str::contains("format      : Elf"))
        .stdout(predicate::str::contains("architecture: x86_64"))
        .stdout(predicate::str::contains("[.text]"))
        .stdout(predicate::str::contains("<entry>:"))
        .stdout(predicate::str::contains("push"))
        .stdout(predicate::str::contains("[.init]"))
        .stdout(predicate::str::contains("<init_func>:"));

    fs::remove_file(path).unwrap();
}

#[test]
fn cli_requires_explicit_mode_for_arm_object_files() {
    let path = unique_temp_path("thumb-fixture.o");
    write_thumb_test_object(&path);

    let mut command = Command::cargo_bin("assembler").unwrap();
    command
        .arg(&path)
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "ARM binaries require explicit mode selection",
        ))
        .stderr(predicate::str::contains("--arch arm or --arch thumb"));

    fs::remove_file(path).unwrap();
}

#[test]
fn cli_disassembles_thumb_object_file_when_overridden() {
    let path = unique_temp_path("thumb-fixture-explicit.o");
    write_thumb_test_object(&path);

    let mut command = Command::cargo_bin("assembler").unwrap();
    command
        .arg(&path)
        .args(["--arch", "thumb"])
        .assert()
        .success()
        .stdout(predicate::str::contains("architecture: thumb"))
        .stdout(predicate::str::contains("<thumb_entry>:"))
        .stdout(predicate::str::contains("nop"));

    fs::remove_file(path).unwrap();
}

#[test]
fn cli_disassembles_thumb_symbol_with_lsb_set() {
    let path = unique_temp_path("thumb-lsb-symbol.o");
    write_thumb_lsb_symbol_test_object(&path);

    let mut command = Command::cargo_bin("assembler").unwrap();
    command
        .arg(&path)
        .args(["--arch", "thumb", "--symbol", "thumb_entry"])
        .assert()
        .success()
        .stdout(predicate::str::contains("[.text::thumb_entry]"))
        .stdout(predicate::str::contains("<thumb_entry>:"))
        .stdout(predicate::str::contains("nop"));

    fs::remove_file(path).unwrap();
}

#[test]
fn cli_rejects_big_endian_aarch64_object_files() {
    let path = unique_temp_path("big-endian-aarch64.o");
    write_big_endian_aarch64_test_object(&path);

    let mut command = Command::cargo_bin("assembler").unwrap();
    command
        .arg(&path)
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "big-endian objects are not currently supported for aarch64 disassembly",
        ));

    fs::remove_file(path).unwrap();
}

#[test]
fn cli_can_disassemble_specific_symbol_only() {
    let path = unique_temp_path("symbol-filter.o");
    write_test_object(&path);

    let mut command = Command::cargo_bin("assembler").unwrap();
    command
        .arg(&path)
        .args(["--symbol", "entry"])
        .assert()
        .success()
        .stdout(predicate::str::contains("symbols     : entry"))
        .stdout(predicate::str::contains("[.text::entry]"))
        .stdout(predicate::str::contains("push"))
        .stdout(predicate::str::contains("[.init]").not())
        .stdout(predicate::str::contains("<init_func>:").not())
        .stdout(predicate::str::contains("nop").not());

    fs::remove_file(path).unwrap();
}

#[test]
fn cli_can_analyze_specific_symbol_from_object_file() {
    let path = unique_temp_path("symbol-analyze.o");
    write_test_object(&path);

    let mut command = Command::cargo_bin("assembler").unwrap();
    command
        .arg(&path)
        .args(["--symbol", "entry", "--analyze"])
        .assert()
        .success()
        .stdout(predicate::str::contains("symbols     : entry"))
        .stdout(predicate::str::contains("analysis     : enabled"))
        .stdout(predicate::str::contains(
            "No supported memory-safety findings were identified",
        ));

    fs::remove_file(path).unwrap();
}

#[test]
fn cli_rejects_unknown_symbol_filter() {
    let path = unique_temp_path("missing-symbol.o");
    write_test_object(&path);

    let mut command = Command::cargo_bin("assembler").unwrap();
    command
        .arg(&path)
        .args(["--symbol", "missing_symbol"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "requested symbol(s) not found or not disassemblable: missing_symbol",
        ));

    fs::remove_file(path).unwrap();
}

#[test]
fn cli_escapes_unknown_symbol_name_in_error() {
    let path = unique_temp_path("escaped-missing-symbol.o");
    write_test_object(&path);

    let mut command = Command::cargo_bin("assembler").unwrap();
    command
        .arg(&path)
        .args(["--symbol", "bad\n\u{1b}[31mname"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("bad\\n\\u{1b}[31mname"));

    fs::remove_file(path).unwrap();
}

#[test]
fn cli_rejects_symbol_filter_for_raw_hex_input() {
    let mut command = Command::cargo_bin("assembler").unwrap();
    command
        .args(["--raw-hex", "c3", "--arch", "x86-64", "--symbol", "entry"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "--symbol is only supported when disassembling files",
        ));
}

#[test]
fn cli_rejects_section_filter_for_raw_hex_input() {
    let mut command = Command::cargo_bin("assembler").unwrap();
    command
        .args(["--raw-hex", "c3", "--arch", "x86-64", "--section", ".text"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "--section is only supported when disassembling files",
        ));
}

#[test]
fn cli_rejects_all_sections_for_raw_hex_input() {
    let mut command = Command::cargo_bin("assembler").unwrap();
    command
        .args(["--raw-hex", "c3", "--arch", "x86-64", "--all-sections"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "--all-sections is only supported when disassembling files",
        ));
}

#[test]
fn cli_can_emit_json_output_with_analysis() {
    let output = Command::cargo_bin("assembler")
        .unwrap()
        .args([
            "--raw-hex",
            "55 48 89 e5 48 83 ec 20 31 c0 c6 44 05 f0 41 48 83 c0 01 48 83 f8 40 75 f1 c9 c3",
            "--arch",
            "x86-64",
            "--analyze",
            "--output",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let value: Value = serde_json::from_slice(&output).unwrap();
    assert!(value.get("disassembly").is_some());
    assert!(value.get("analysis").is_some());
    assert!(value["analysis"]["findings"].is_array());
}

#[test]
fn cli_can_exit_non_zero_when_analysis_finds_risk() {
    Command::cargo_bin("assembler")
        .unwrap()
        .args([
            "--raw-hex",
            "55 48 89 e5 48 83 ec 20 31 c0 c6 44 05 f0 41 48 83 c0 01 48 83 f8 40 75 f1 c9 c3",
            "--arch",
            "x86-64",
            "--analyze",
            "--analyze-exit-code",
        ])
        .assert()
        .code(1)
        .stdout(predicate::str::contains(
            "potential-stack-buffer-write-risk",
        ));
}

#[test]
fn cli_filters_to_requested_sections_on_object_file() {
    let path = unique_temp_path("sections.o");
    write_test_object(&path);

    let mut command = Command::cargo_bin("assembler").unwrap();
    command
        .arg(&path)
        .args(["--section", ".init"])
        .assert()
        .success()
        .stdout(predicate::str::contains("[.init]"))
        .stdout(predicate::str::contains("<init_func>:"))
        .stdout(predicate::str::contains("nop"))
        .stdout(predicate::str::contains("push").not())
        .stdout(predicate::str::contains("[.text]").not())
        .stdout(predicate::str::contains("mov").not());

    fs::remove_file(path).unwrap();
}

#[test]
fn cli_accepts_repeated_section_filters_on_object_file() {
    let path = unique_temp_path("multi-sections.o");
    write_test_object(&path);

    let mut command = Command::cargo_bin("assembler").unwrap();
    command
        .arg(&path)
        .args(["--section", ".init", "--section", ".text"])
        .assert()
        .success()
        .stdout(predicate::str::contains("[.init]"))
        .stdout(predicate::str::contains("[.text]"))
        .stdout(predicate::str::contains("<init_func>:"))
        .stdout(predicate::str::contains("<entry>:"));

    fs::remove_file(path).unwrap();
}
