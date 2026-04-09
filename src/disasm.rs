use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use capstone::{Capstone, arch, prelude::*};
use object::{
    Architecture as ObjectArchitecture, Endianness, Object, ObjectSection, ObjectSymbol,
    SectionKind, SymbolKind, SymbolSection,
};

const MAX_INPUT_FILE_SIZE: u64 = 128 * 1024 * 1024;
const MAX_RAW_INPUT_BYTES: usize = 8 * 1024;

use crate::render::escape_for_terminal;
pub(crate) use crate::types::{
    Architecture, DisasmInput, DisasmRequest, DisassembledSection, DisassemblyReport, Instruction,
    InstructionDetail, OperandAccess, OperandDetail, Syntax,
};

pub fn disassemble(request: DisasmRequest) -> Result<DisassemblyReport> {
    match &request.input {
        DisasmInput::File(path) => disassemble_file(path, &request),
        DisasmInput::RawHex(raw) => disassemble_raw(raw, &request),
    }
}

fn disassemble_file(path: &PathBuf, request: &DisasmRequest) -> Result<DisassemblyReport> {
    let safe_path = escaped_path(path);
    let metadata =
        fs::metadata(path).with_context(|| format!("failed to inspect input file {safe_path}"))?;
    ensure!(
        metadata.is_file(),
        "input path is not a regular file: {}",
        safe_path
    );
    ensure!(
        metadata.len() <= MAX_INPUT_FILE_SIZE,
        "input file is too large ({} bytes). Refusing to read files larger than {} bytes",
        metadata.len(),
        MAX_INPUT_FILE_SIZE
    );

    let bytes = fs::read(path).with_context(|| format!("failed to read input file {safe_path}"))?;
    let file = object::File::parse(&*bytes)
        .with_context(|| format!("failed to parse executable {safe_path}"))?;

    let architecture = resolve_file_architecture(&file, request.architecture)?;

    let capstone = build_capstone(architecture, request.syntax, request.analyze)?;

    if !request.symbols.is_empty() {
        let sections = disassemble_requested_symbols(&file, &capstone, request)?;
        let mut metadata = vec![
            ("format".into(), format!("{:?}", file.format())),
            (
                "endianness".into(),
                format_endianness(file.endianness()).into(),
            ),
            (
                "architecture".into(),
                architecture.display_name().to_string(),
            ),
            (
                "word-size".into(),
                if file.is_64() { "64-bit" } else { "32-bit" }.into(),
            ),
            ("entry".into(), format!("{:#x}", file.entry())),
            ("symbols".into(), request.symbols.join(", ")),
        ];

        if architecture.supports_syntax_metadata() {
            metadata.push(("syntax".into(), request.syntax.display_name().into()));
        }

        if !request.sections.is_empty() {
            metadata.push(("filter".into(), request.sections.join(", ")));
        }

        return Ok(DisassemblyReport {
            target: path.display().to_string(),
            architecture,
            metadata,
            sections,
        });
    }

    let mut sections = Vec::new();
    for section in file.sections() {
        let Ok(name) = section.name() else {
            continue;
        };
        let safe_name = escape_for_terminal(name);

        if !should_disassemble_section(name, section.kind(), section.size(), request) {
            continue;
        }

        let data = section
            .data()
            .with_context(|| format!("failed to read section data for {safe_name}"))?;

        if data.is_empty() {
            continue;
        }

        let instructions = disassemble_bytes(&capstone, data, section.address(), request.analyze)
            .with_context(|| format!("failed to disassemble section {safe_name}"))?;

        sections.push(DisassembledSection {
            name: name.to_owned(),
            address: section.address(),
            size: section.size(),
            labels: collect_section_labels_for_range(
                &file,
                section.index(),
                section.address(),
                section.size(),
            ),
            instructions,
        });
    }

    ensure!(
        !sections.is_empty(),
        "no matching sections were found to disassemble"
    );

    let mut metadata = vec![
        ("format".into(), format!("{:?}", file.format())),
        (
            "endianness".into(),
            format_endianness(file.endianness()).into(),
        ),
        (
            "architecture".into(),
            architecture.display_name().to_string(),
        ),
        (
            "word-size".into(),
            if file.is_64() { "64-bit" } else { "32-bit" }.into(),
        ),
        ("entry".into(), format!("{:#x}", file.entry())),
    ];

    if architecture.supports_syntax_metadata() {
        metadata.push(("syntax".into(), request.syntax.display_name().into()));
    }

    if !request.sections.is_empty() {
        metadata.push(("filter".into(), request.sections.join(", ")));
    }

    Ok(DisassemblyReport {
        target: path.display().to_string(),
        architecture,
        metadata,
        sections,
    })
}

fn resolve_file_architecture(
    file: &object::File<'_>,
    requested_architecture: Option<Architecture>,
) -> Result<Architecture> {
    if let Some(architecture) = requested_architecture {
        return Ok(architecture);
    }

    match file.architecture() {
        ObjectArchitecture::Arm => {
            bail!("ARM binaries require explicit mode selection; pass --arch arm or --arch thumb")
        }
        architecture => Architecture::from_object(architecture)
            .ok_or_else(|| anyhow!("unsupported or unknown architecture: {:?}", architecture)),
    }
}

fn disassemble_raw(raw_hex: &str, request: &DisasmRequest) -> Result<DisassemblyReport> {
    let architecture = request
        .architecture
        .ok_or_else(|| anyhow!("--arch is required when disassembling raw bytes with --raw-hex"))?;
    ensure!(
        request.symbols.is_empty(),
        "--symbol is only supported when disassembling files"
    );
    ensure!(
        request.sections.is_empty(),
        "--section is only supported when disassembling files"
    );
    ensure!(
        !request.all_sections,
        "--all-sections is only supported when disassembling files"
    );
    let bytes = parse_hex_bytes(raw_hex)?;
    let capstone = build_capstone(architecture, request.syntax, request.analyze)?;
    let instructions = disassemble_bytes(&capstone, &bytes, request.base_address, request.analyze)
        .context("failed to disassemble raw bytes")?;

    Ok(DisassemblyReport {
        target: "<raw-hex>".into(),
        architecture,
        metadata: raw_metadata(architecture, request, bytes.len()),
        sections: vec![DisassembledSection {
            name: "raw".into(),
            address: request.base_address,
            size: bytes.len() as u64,
            labels: BTreeMap::new(),
            instructions,
        }],
    })
}

fn raw_metadata(
    architecture: Architecture,
    request: &DisasmRequest,
    byte_count: usize,
) -> Vec<(String, String)> {
    let mut metadata = vec![
        ("architecture".into(), architecture.display_name().into()),
        (
            "base-address".into(),
            format!("{:#x}", request.base_address),
        ),
        ("byte-count".into(), byte_count.to_string()),
    ];

    if architecture.supports_syntax_metadata() {
        metadata.push(("syntax".into(), request.syntax.display_name().into()));
    }

    metadata
}

fn build_capstone(architecture: Architecture, syntax: Syntax, detail: bool) -> Result<Capstone> {
    let capstone = match architecture {
        Architecture::X86 => Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode32)
            .syntax(map_x86_syntax(syntax))
            .detail(detail)
            .build(),
        Architecture::X86_64 => Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .syntax(map_x86_syntax(syntax))
            .detail(detail)
            .build(),
        Architecture::Arm => Capstone::new()
            .arm()
            .mode(arch::arm::ArchMode::Arm)
            .detail(detail)
            .build(),
        Architecture::Thumb => Capstone::new()
            .arm()
            .mode(arch::arm::ArchMode::Thumb)
            .detail(detail)
            .build(),
        Architecture::Aarch64 => Capstone::new()
            .arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .detail(detail)
            .build(),
    };

    capstone.map_err(|error| anyhow!("failed to initialize disassembler: {error}"))
}

fn map_x86_syntax(syntax: Syntax) -> arch::x86::ArchSyntax {
    match syntax {
        Syntax::Intel => arch::x86::ArchSyntax::Intel,
        Syntax::Att => arch::x86::ArchSyntax::Att,
    }
}

fn disassemble_bytes(
    capstone: &Capstone,
    bytes: &[u8],
    address: u64,
    with_detail: bool,
) -> Result<Vec<Instruction>> {
    let instructions = capstone
        .disasm_all(bytes, address)
        .map_err(|error| anyhow!("capstone failed to decode bytes at {address:#x}: {error}"))?;

    instructions
        .iter()
        .map(|instruction| {
            let detail = if with_detail {
                Some(extract_instruction_detail(capstone, instruction)?)
            } else {
                None
            };

            Ok(Instruction {
                address: instruction.address(),
                bytes: instruction.bytes().to_vec(),
                mnemonic: instruction.mnemonic().unwrap_or("<unknown>").to_owned(),
                operands: instruction.op_str().unwrap_or_default().to_owned(),
                detail,
            })
        })
        .collect::<Result<Vec<_>>>()
}

fn extract_instruction_detail(
    capstone: &Capstone,
    instruction: &capstone::Insn<'_>,
) -> Result<InstructionDetail> {
    let detail = capstone.insn_detail(instruction).map_err(|error| {
        anyhow!(
            "failed to fetch instruction detail at {:#x}: {error}",
            instruction.address()
        )
    })?;
    let arch_detail = detail.arch_detail();
    let Some(x86_detail) = arch_detail.x86() else {
        return Ok(InstructionDetail::default());
    };

    let groups = detail
        .groups()
        .iter()
        .filter_map(|group| capstone.group_name(*group))
        .collect();
    let operands = x86_detail
        .operands()
        .map(|operand| map_x86_operand(capstone, operand))
        .collect();

    Ok(InstructionDetail { groups, operands })
}

fn map_x86_operand(capstone: &Capstone, operand: arch::x86::X86Operand) -> OperandDetail {
    use arch::x86::X86OperandType;

    match operand.op_type {
        X86OperandType::Reg(reg_id) => OperandDetail::Register {
            name: resolve_reg_name(capstone, reg_id),
            access: operand.access.map(map_operand_access),
            size: operand.size,
        },
        X86OperandType::Imm(value) => OperandDetail::Immediate {
            value,
            size: operand.size,
        },
        X86OperandType::Mem(memory) => OperandDetail::Memory {
            segment: resolve_reg_name(capstone, memory.segment()),
            base: resolve_reg_name(capstone, memory.base()),
            index: resolve_reg_name(capstone, memory.index()),
            scale: memory.scale(),
            disp: memory.disp(),
            access: operand.access.map(map_operand_access),
            size: operand.size,
        },
        X86OperandType::Invalid => OperandDetail::Invalid,
    }
}

fn resolve_reg_name(capstone: &Capstone, reg_id: RegId) -> Option<String> {
    if reg_id.0 == 0 {
        None
    } else {
        capstone.reg_name(reg_id)
    }
}

fn map_operand_access(access: capstone::RegAccessType) -> OperandAccess {
    match access {
        capstone::RegAccessType::ReadOnly => OperandAccess::ReadOnly,
        capstone::RegAccessType::WriteOnly => OperandAccess::WriteOnly,
        capstone::RegAccessType::ReadWrite => OperandAccess::ReadWrite,
    }
}

fn should_disassemble_section(
    name: &str,
    kind: SectionKind,
    size: u64,
    request: &DisasmRequest,
) -> bool {
    if size == 0 {
        return false;
    }

    if !request.sections.is_empty() {
        return request.sections.iter().any(|candidate| candidate == name);
    }

    request.all_sections || kind == SectionKind::Text
}

fn collect_section_labels_for_range(
    file: &object::File<'_>,
    target_section: object::SectionIndex,
    address: u64,
    size: u64,
) -> BTreeMap<u64, Vec<String>> {
    let mut labels = BTreeMap::<u64, Vec<String>>::new();

    for symbol in file.symbols().chain(file.dynamic_symbols()) {
        let Ok(name) = symbol.name() else {
            continue;
        };

        if name.is_empty() || !symbol.is_definition() {
            continue;
        }

        if !matches!(symbol.kind(), SymbolKind::Text | SymbolKind::Unknown) {
            continue;
        }

        let SymbolSection::Section(section_index) = symbol.section() else {
            continue;
        };

        if section_index != target_section {
            continue;
        }

        if !(address..address.saturating_add(size)).contains(&symbol.address()) {
            continue;
        }

        labels
            .entry(symbol.address())
            .or_default()
            .push(name.to_owned());
    }

    labels
}

fn disassemble_requested_symbols(
    file: &object::File<'_>,
    capstone: &Capstone,
    request: &DisasmRequest,
) -> Result<Vec<DisassembledSection>> {
    let requested: BTreeSet<&str> = request.symbols.iter().map(String::as_str).collect();
    let mut matched = BTreeSet::new();
    let mut sections = Vec::new();

    for symbol in file.symbols().chain(file.dynamic_symbols()) {
        let Ok(name) = symbol.name() else {
            continue;
        };

        if !requested.contains(name) || !symbol.is_definition() || symbol.size() == 0 {
            continue;
        }

        let object::SymbolSection::Section(section_index) = symbol.section() else {
            continue;
        };
        let section = file.section_by_index(section_index).with_context(|| {
            format!(
                "failed to read section for symbol {}",
                escape_for_terminal(name)
            )
        })?;
        let Ok(section_name) = section.name() else {
            continue;
        };

        if !request.sections.is_empty()
            && !request
                .sections
                .iter()
                .any(|candidate| candidate == section_name)
        {
            continue;
        }

        let data = section.data().with_context(|| {
            format!(
                "failed to read section data for {}",
                escape_for_terminal(section_name)
            )
        })?;
        let relative_start = symbol
            .address()
            .checked_sub(section.address())
            .ok_or_else(|| {
                anyhow!(
                    "symbol {} points outside its containing section",
                    escape_for_terminal(name)
                )
            })?;
        let start = usize::try_from(relative_start).map_err(|_| {
            anyhow!(
                "symbol {} points outside its containing section",
                escape_for_terminal(name)
            )
        })?;
        let size = usize::try_from(symbol.size()).map_err(|_| {
            anyhow!(
                "symbol {} points outside its containing section",
                escape_for_terminal(name)
            )
        })?;
        let end = start.checked_add(size).ok_or_else(|| {
            anyhow!(
                "symbol {} points outside its containing section",
                escape_for_terminal(name)
            )
        })?;
        ensure!(
            end <= data.len(),
            "symbol {} points outside its containing section",
            escape_for_terminal(name)
        );

        let symbol_bytes = &data[start..end];
        let instructions =
            disassemble_bytes(capstone, symbol_bytes, symbol.address(), request.analyze)
                .with_context(|| {
                    format!("failed to disassemble symbol {}", escape_for_terminal(name))
                })?;

        matched.insert(name.to_owned());
        sections.push(DisassembledSection {
            name: format!("{}::{}", section_name, name),
            address: symbol.address(),
            size: symbol.size(),
            labels: collect_section_labels_for_range(
                file,
                section_index,
                symbol.address(),
                symbol.size(),
            ),
            instructions,
        });
    }

    let missing: Vec<&str> = request
        .symbols
        .iter()
        .map(String::as_str)
        .filter(|name| !matched.contains(*name))
        .collect();
    let escaped_missing = missing
        .iter()
        .map(|name| escape_for_terminal(name))
        .collect::<Vec<_>>();
    ensure!(
        missing.is_empty(),
        "requested symbol(s) not found or not disassemblable: {}",
        escaped_missing.join(", ")
    );
    ensure!(
        !sections.is_empty(),
        "no matching symbols were found to disassemble"
    );

    Ok(sections)
}

fn parse_hex_bytes(raw: &str) -> Result<Vec<u8>> {
    let mut nybbles = Vec::with_capacity((MAX_RAW_INPUT_BYTES * 2).min(raw.len()));
    for byte in raw.bytes() {
        match byte {
            b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F' => {
                ensure!(
                    nybbles.len() < MAX_RAW_INPUT_BYTES * 2,
                    "raw hex input exceeds maximum supported size of {} bytes",
                    MAX_RAW_INPUT_BYTES
                );
                nybbles.push(byte)
            }
            b' ' | b'\t' | b'\n' | b'\r' | b'_' | b',' => {}
            _ => bail!(
                "invalid hex character: {}",
                char::from(byte).escape_default()
            ),
        }
    }

    ensure!(!nybbles.is_empty(), "raw byte sequence cannot be empty");
    ensure!(
        nybbles.len() % 2 == 0,
        "raw hex input must contain an even number of nybbles"
    );

    let mut bytes = Vec::with_capacity(nybbles.len() / 2);
    for pair in nybbles.chunks_exact(2) {
        let high = decode_hex_nybble(pair[0]).expect("validated high nybble");
        let low = decode_hex_nybble(pair[1]).expect("validated low nybble");
        bytes.push((high << 4) | low);
    }

    Ok(bytes)
}

fn decode_hex_nybble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn escaped_path(path: &Path) -> String {
    escape_for_terminal(&path.display().to_string())
}

fn format_endianness(endianness: Endianness) -> &'static str {
    match endianness {
        Endianness::Little => "little",
        Endianness::Big => "big",
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Architecture, DisasmInput, DisasmRequest, DisassembledSection, DisassemblyReport,
        Instruction, MAX_RAW_INPUT_BYTES, Syntax, disassemble, escape_for_terminal,
        parse_hex_bytes, should_disassemble_section,
    };
    use crate::render::{render_box, render_section_box, style_operands, styled_key_value_line};
    use crate::types::RenderOptions;
    use std::collections::BTreeMap;
    use std::panic;

    use object::SectionKind;
    use unicode_width::UnicodeWidthStr;

    fn sample_section() -> DisassembledSection {
        DisassembledSection {
            name: ".text".into(),
            address: 0x1000,
            size: 6,
            labels: BTreeMap::from([(0x1000, vec!["entry".into()])]),
            instructions: vec![
                Instruction {
                    address: 0x1000,
                    bytes: vec![0x55],
                    mnemonic: "push".into(),
                    operands: "rbp".into(),
                    detail: None,
                },
                Instruction {
                    address: 0x1001,
                    bytes: vec![0x48, 0x89, 0xe5],
                    mnemonic: "mov".into(),
                    operands: "rbp, rsp".into(),
                    detail: None,
                },
                Instruction {
                    address: 0x1004,
                    bytes: vec![0x5d],
                    mnemonic: "pop".into(),
                    operands: "rbp".into(),
                    detail: None,
                },
                Instruction {
                    address: 0x1005,
                    bytes: vec![0xc3],
                    mnemonic: "ret".into(),
                    operands: String::new(),
                    detail: None,
                },
            ],
        }
    }

    fn sample_report() -> DisassemblyReport {
        DisassemblyReport {
            target: "<test>".into(),
            architecture: Architecture::X86_64,
            metadata: vec![
                ("architecture".into(), "x86_64".into()),
                ("base-address".into(), "0x0".into()),
                ("syntax".into(), "intel".into()),
                ("byte-count".into(), "6".into()),
            ],
            sections: vec![sample_section()],
        }
    }

    fn strip_ansi(value: &str) -> String {
        let bytes = value.as_bytes();
        let mut output = String::new();
        let mut index = 0;

        while index < bytes.len() {
            if bytes[index] == 0x1b {
                index += 1;
                if index < bytes.len() && bytes[index] == b'[' {
                    index += 1;
                    while index < bytes.len() {
                        let byte = bytes[index];
                        index += 1;
                        if (b'@'..=b'~').contains(&byte) {
                            break;
                        }
                    }
                }
                continue;
            }

            let character = value[index..]
                .chars()
                .next()
                .expect("valid UTF-8 character while stripping ANSI");
            output.push(character);
            index += character.len_utf8();
        }

        output
    }

    fn visible_line_width(line: &str) -> usize {
        UnicodeWidthStr::width(strip_ansi(line).as_str())
    }

    fn assert_uniform_box_widths(rendered: &str) {
        let lines: Vec<&str> = rendered.lines().collect();
        assert!(lines.len() >= 2, "box should span at least two lines");
        let expected = visible_line_width(lines[0]);

        for line in lines {
            assert_eq!(
                visible_line_width(line),
                expected,
                "line width mismatch for {line:?}"
            );
        }
    }

    #[test]
    fn parses_spaced_hex_bytes() {
        assert_eq!(
            parse_hex_bytes("55 48 89 e5").unwrap(),
            vec![0x55, 0x48, 0x89, 0xe5]
        );
    }

    #[test]
    fn rejects_odd_hex_length() {
        assert!(parse_hex_bytes("abc").is_err());
    }

    #[test]
    fn rejects_non_ascii_hex_without_panicking() {
        let result = panic::catch_unwind(|| parse_hex_bytes("€€"));
        assert!(result.is_ok());
        assert!(result.unwrap().is_err());
    }

    #[test]
    fn raw_disassembly_requires_architecture() {
        let request = DisasmRequest {
            input: DisasmInput::RawHex("c3".into()),
            architecture: None,
            syntax: Syntax::Intel,
            base_address: 0,
            all_sections: false,
            sections: Vec::new(),
            symbols: Vec::new(),
            analyze: false,
        };

        assert!(disassemble(request).is_err());
    }

    #[test]
    fn raw_x86_disassembly_produces_ret() {
        let request = DisasmRequest {
            input: DisasmInput::RawHex("c3".into()),
            architecture: Some(Architecture::X86_64),
            syntax: Syntax::Intel,
            base_address: 0x401000,
            all_sections: false,
            sections: Vec::new(),
            symbols: Vec::new(),
            analyze: false,
        };

        let report = disassemble(request).unwrap().to_string();
        assert!(report.contains("ret"));
        assert!(report.contains("0x0000000000401000"));
    }

    #[test]
    fn section_filters_override_executable_only_default() {
        let request = DisasmRequest {
            input: DisasmInput::RawHex(String::new()),
            architecture: None,
            syntax: Syntax::Intel,
            base_address: 0,
            all_sections: false,
            sections: vec![".init".into()],
            symbols: Vec::new(),
            analyze: false,
        };

        assert!(should_disassemble_section(
            ".init",
            SectionKind::Data,
            16,
            &request
        ));
        assert!(!should_disassemble_section(
            ".text",
            SectionKind::Text,
            16,
            &request
        ));
    }

    #[test]
    fn labeled_output_preserves_instruction_order() {
        let report = DisassemblyReport {
            target: "<test>".into(),
            architecture: Architecture::X86_64,
            metadata: Vec::new(),
            sections: vec![DisassembledSection {
                name: ".text".into(),
                address: 0x1000,
                size: 2,
                labels: BTreeMap::from([(0x1001, vec!["next".into()])]),
                instructions: vec![
                    Instruction {
                        address: 0x1000,
                        bytes: vec![0x90],
                        mnemonic: "nop".into(),
                        operands: String::new(),
                        detail: None,
                    },
                    Instruction {
                        address: 0x1001,
                        bytes: vec![0xc3],
                        mnemonic: "ret".into(),
                        operands: String::new(),
                        detail: None,
                    },
                ],
            }],
        };

        let rendered = report.to_string();
        let nop_index = rendered.find("0x0000000000001000").unwrap();
        let label_index = rendered.find("0x0000000000001001 <next>:").unwrap();
        let ret_index = rendered.rfind("0x0000000000001001").unwrap();

        assert!(nop_index < label_index);
        assert!(label_index < ret_index);
    }

    #[test]
    fn pretty_render_without_color_has_no_ansi_sequences() {
        let report = sample_report();

        let rendered = report.render(&RenderOptions::pretty(false));
        assert!(rendered.contains("╭─ DISASSEMBLY"));
        assert!(rendered.contains("SECTION .text"));
        assert!(!rendered.contains("\u{1b}["));
    }

    #[test]
    fn pretty_render_with_color_emits_ansi_sequences() {
        let report = sample_report();

        let rendered = report.render(&RenderOptions::pretty(true));
        assert!(rendered.contains("\u{1b}["));
    }

    #[test]
    fn header_box_has_uniform_visible_widths() {
        let box_render = render_box(
            "disassembly",
            "DISASSEMBLY",
            &[
                styled_key_value_line("target", "<raw-hex>".into(), false),
                styled_key_value_line("architecture", "x86_64".into(), false),
                styled_key_value_line("byte-count", "6".into(), false),
            ],
        );

        assert_uniform_box_widths(&box_render);
    }

    #[test]
    fn colored_header_metadata_keeps_key_alignment() {
        let rendered = sample_report().render(&RenderOptions::pretty(true));
        let stripped = strip_ansi(&rendered);

        assert!(stripped.contains("target       <test>"));
        assert!(stripped.contains("architecture x86_64"));
        assert!(stripped.contains("base-address 0x0"));
        assert!(stripped.contains("syntax       intel"));
        assert!(stripped.contains("byte-count   6"));
    }

    #[test]
    fn section_box_has_uniform_visible_widths_without_color() {
        let box_render = render_section_box(&sample_section(), false);
        assert_uniform_box_widths(&box_render);
    }

    #[test]
    fn section_box_has_uniform_visible_widths_with_color() {
        let box_render = render_section_box(&sample_section(), true);
        assert_uniform_box_widths(&box_render);
    }

    #[test]
    fn pretty_render_ends_with_newline() {
        let rendered = sample_report().render(&RenderOptions::pretty(false));
        assert!(rendered.ends_with('\n'));
    }

    #[test]
    fn terminal_output_is_escaped() {
        assert_eq!(
            escape_for_terminal("bad\n\x1b[31mname"),
            "bad\\n\\u{1b}[31mname"
        );
    }

    #[test]
    fn mnemonic_output_is_escaped_in_plain_and_pretty_modes() {
        let report = DisassemblyReport {
            target: "<test>".into(),
            architecture: Architecture::X86_64,
            metadata: Vec::new(),
            sections: vec![DisassembledSection {
                name: ".text".into(),
                address: 0x1000,
                size: 1,
                labels: BTreeMap::new(),
                instructions: vec![Instruction {
                    address: 0x1000,
                    bytes: vec![0xc3],
                    mnemonic: "ret\n\x1b[31mboom".into(),
                    operands: String::new(),
                    detail: None,
                }],
            }],
        };

        let plain = report.render(&RenderOptions::plain(false));
        let pretty = report.render(&RenderOptions::pretty(false));

        assert!(plain.contains("ret\\n\\u{1b}[31mboom"));
        assert!(pretty.contains("ret\\n\\u{1b}[31mboom"));
    }

    #[test]
    fn label_and_operand_output_are_escaped_in_pretty_mode() {
        let report = DisassemblyReport {
            target: "<test>".into(),
            architecture: Architecture::X86_64,
            metadata: Vec::new(),
            sections: vec![DisassembledSection {
                name: ".text".into(),
                address: 0x1000,
                size: 1,
                labels: BTreeMap::from([(0x1000, vec!["evil\n\x1b[31mlabel".into()])]),
                instructions: vec![Instruction {
                    address: 0x1000,
                    bytes: vec![0xc3],
                    mnemonic: "ret".into(),
                    operands: "rax, \n\x1b[31mboom".into(),
                    detail: None,
                }],
            }],
        };

        let pretty = report.render(&RenderOptions::pretty(false));
        assert!(pretty.contains("evil\\n\\u{1b}[31mlabel"));
        assert!(pretty.contains("\\n"));
        assert!(pretty.contains("\\u{1b}"));
        assert!(!pretty.contains("\n\x1b[31mboom"));
    }

    #[test]
    fn long_labels_render_without_truncation() {
        let mut section = sample_section();
        section.labels = BTreeMap::from([(0x1000, vec!["L".repeat(256)])]);

        let rendered = render_section_box(&section, false);

        assert_uniform_box_widths(&rendered);
        assert!(rendered.contains(&"L".repeat(256)));
    }

    #[test]
    fn pretty_render_large_report_keeps_full_operands_visible() {
        let instructions = (0..128)
            .map(|index| Instruction {
                address: 0x1000 + index,
                bytes: vec![0x90],
                mnemonic: "mov".into(),
                operands: format!("rax, {}", "L".repeat(128)),
                detail: None,
            })
            .collect();
        let section = DisassembledSection {
            name: ".text".into(),
            address: 0x1000,
            size: 128,
            labels: BTreeMap::new(),
            instructions,
        };

        let rendered = render_section_box(&section, false);

        assert!(rendered.contains(&"L".repeat(128)));
        assert_uniform_box_widths(&rendered);
    }

    #[test]
    fn style_operands_handles_att_and_negative_immediates() {
        let styled = style_operands(" $0x10, $-8, %rbp ", false);
        assert!(styled.contains("$0x10"));
        assert!(styled.contains("$-8"));
        assert!(styled.contains("%rbp"));
    }

    #[test]
    fn style_operands_preserves_register_families() {
        let styled = style_operands(" %xmm1, x2, wzr, wsp, fpcr, fpsr, daif, rax ", false);
        assert!(styled.contains("%xmm1"));
        assert!(styled.contains("x2"));
        assert!(styled.contains("wzr"));
        assert!(styled.contains("wsp"));
        assert!(styled.contains("fpcr"));
        assert!(styled.contains("fpsr"));
        assert!(styled.contains("daif"));
        assert!(styled.contains("rax"));
    }

    #[test]
    fn rejects_raw_hex_input_over_limit() {
        let too_large = "aa".repeat(MAX_RAW_INPUT_BYTES + 1);
        let error = parse_hex_bytes(&too_large).unwrap_err().to_string();
        assert!(error.contains("raw hex input exceeds maximum supported size"));
    }
}
