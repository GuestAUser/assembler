use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::{self, Display, Write as _},
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use capstone::{Capstone, arch, prelude::*};
use object::{
    Architecture as ObjectArchitecture, Endianness, Object, ObjectSection, ObjectSymbol,
    SectionKind, SymbolKind, SymbolSection,
};
use unicode_width::UnicodeWidthStr;

const MAX_RENDERED_INSTRUCTION_BYTES: usize = 16;
const BYTE_COLUMN_WIDTH: usize = MAX_RENDERED_INSTRUCTION_BYTES * 3;
const MAX_INPUT_FILE_SIZE: u64 = 128 * 1024 * 1024;
const MNEMONIC_COLUMN_WIDTH: usize = 12;
const MAX_RAW_INPUT_BYTES: usize = 8 * 1024;

#[derive(Clone, Debug)]
pub struct DisasmRequest {
    pub input: DisasmInput,
    pub architecture: Option<Architecture>,
    pub syntax: Syntax,
    pub base_address: u64,
    pub all_sections: bool,
    pub sections: Vec<String>,
    pub symbols: Vec<String>,
}

#[derive(Clone, Debug)]
pub enum DisasmInput {
    File(PathBuf),
    RawHex(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Architecture {
    X86,
    X86_64,
    Arm,
    Thumb,
    Aarch64,
}

impl Architecture {
    fn from_object(architecture: ObjectArchitecture) -> Option<Self> {
        match architecture {
            ObjectArchitecture::I386 => Some(Self::X86),
            ObjectArchitecture::X86_64 => Some(Self::X86_64),
            ObjectArchitecture::Arm => Some(Self::Arm),
            ObjectArchitecture::Aarch64 | ObjectArchitecture::Aarch64_Ilp32 => Some(Self::Aarch64),
            _ => None,
        }
    }

    fn display_name(self) -> &'static str {
        match self {
            Self::X86 => "x86",
            Self::X86_64 => "x86_64",
            Self::Arm => "arm",
            Self::Thumb => "thumb",
            Self::Aarch64 => "aarch64",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Syntax {
    Intel,
    Att,
}

impl Syntax {
    fn display_name(self) -> &'static str {
        match self {
            Self::Intel => "intel",
            Self::Att => "att",
        }
    }
}

pub fn disassemble(request: DisasmRequest) -> Result<DisassemblyReport> {
    match &request.input {
        DisasmInput::File(path) => disassemble_file(path, &request),
        DisasmInput::RawHex(raw) => disassemble_raw(raw, &request),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RenderOptions {
    pretty: bool,
    color_enabled: bool,
}

impl RenderOptions {
    pub fn plain(color_enabled: bool) -> Self {
        Self {
            pretty: false,
            color_enabled,
        }
    }

    pub fn pretty(color_enabled: bool) -> Self {
        Self {
            pretty: true,
            color_enabled,
        }
    }
}

#[derive(Debug)]
pub struct DisassemblyReport {
    target: String,
    metadata: Vec<(String, String)>,
    sections: Vec<DisassembledSection>,
}

impl DisassemblyReport {
    pub fn render(&self, options: &RenderOptions) -> String {
        if options.pretty {
            self.render_pretty(options.color_enabled)
        } else {
            self.render_plain(options.color_enabled)
        }
    }

    fn render_plain(&self, color_enabled: bool) -> String {
        let mut output = String::with_capacity(self.estimated_plain_capacity());

        let target = escape_for_terminal(&self.target);
        let _ = writeln!(
            output,
            "{}: {}",
            style_meta_key("target       ", color_enabled),
            style_meta_value(&target, color_enabled)
        );
        for (key, value) in &self.metadata {
            let padded_key = format!("{key:<12}");
            let safe_value = escape_for_terminal(value);
            let _ = writeln!(
                output,
                "{}: {}",
                style_meta_key(&padded_key, color_enabled),
                style_meta_value(&safe_value, color_enabled)
            );
        }

        for section in &self.sections {
            let _ = writeln!(output);
            let safe_name = escape_for_terminal(&section.name);
            let _ = writeln!(
                output,
                "[{}] {}={} {}={} {}={}",
                style_section_name(&safe_name, color_enabled),
                style_meta_key("addr", color_enabled),
                style_address(&format_address(section.address), color_enabled),
                style_meta_key("size", color_enabled),
                style_number(&format!("{:#x}", section.size), color_enabled),
                style_meta_key("instructions", color_enabled),
                style_number(&section.instructions.len().to_string(), color_enabled)
            );

            let mut emitted_addresses = BTreeSet::new();
            for instruction in &section.instructions {
                if let Some(labels) = section.labels.get(&instruction.address) {
                    for label in labels {
                        let safe_label = escape_for_terminal(label);
                        let _ = writeln!(
                            output,
                            "{} <{}>:",
                            style_address(&format_address(instruction.address), color_enabled),
                            style_label(&safe_label, color_enabled)
                        );
                    }
                }

                let _ = writeln!(output, "  {}", instruction.render_plain(color_enabled));
                emitted_addresses.insert(instruction.address);
            }

            if section.instructions.is_empty() {
                let _ = writeln!(output, "  <no instructions decoded>");
            }

            for (address, labels) in &section.labels {
                if emitted_addresses.contains(address) {
                    continue;
                }

                for label in labels {
                    let safe_label = escape_for_terminal(label);
                    let _ = writeln!(
                        output,
                        "{} <{}>:",
                        style_address(&format_address(*address), color_enabled),
                        style_label(&safe_label, color_enabled)
                    );
                }
            }
        }

        output
    }

    fn render_pretty(&self, color_enabled: bool) -> String {
        let mut output = String::with_capacity(self.estimated_pretty_capacity());

        let mut header_lines = Vec::with_capacity(self.metadata.len() + 1);
        header_lines.push(styled_key_value_line(
            "target",
            escape_for_terminal(&self.target),
            color_enabled,
        ));

        for (key, value) in &self.metadata {
            header_lines.push(styled_key_value_line(
                key,
                escape_for_terminal(value),
                color_enabled,
            ));
        }

        output.push_str(&render_box(
            "disassembly",
            &style_box_title("DISASSEMBLY", color_enabled),
            &header_lines,
        ));

        for section in &self.sections {
            output.push('\n');
            output.push_str(&render_section_box(section, color_enabled));
        }

        output.push('\n');

        output
    }

    fn estimated_plain_capacity(&self) -> usize {
        let instruction_count: usize = self
            .sections
            .iter()
            .map(|section| section.instructions.len())
            .sum();
        128 + (self.metadata.len() * 32) + (self.sections.len() * 64) + (instruction_count * 96)
    }

    fn estimated_pretty_capacity(&self) -> usize {
        let instruction_count: usize = self
            .sections
            .iter()
            .map(|section| section.instructions.len())
            .sum();
        256 + (self.metadata.len() * 48) + (self.sections.len() * 128) + (instruction_count * 128)
    }
}

impl Display for DisassemblyReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render(&RenderOptions::plain(false)))
    }
}

#[derive(Debug)]
struct StyledLine {
    plain: String,
    styled: String,
}

impl StyledLine {
    fn plain(text: String) -> Self {
        Self {
            plain: text.clone(),
            styled: text,
        }
    }

    fn styled(plain: String, styled: String) -> Self {
        Self { plain, styled }
    }
}

#[derive(Debug)]
struct DisassembledSection {
    name: String,
    address: u64,
    size: u64,
    labels: BTreeMap<u64, Vec<String>>,
    instructions: Vec<Instruction>,
}

#[derive(Debug)]
struct Instruction {
    address: u64,
    bytes: Vec<u8>,
    mnemonic: String,
    operands: String,
}

impl Instruction {
    fn render_plain(&self, color_enabled: bool) -> String {
        let mnemonic = escape_for_terminal(&self.mnemonic);
        let operands = if self.operands.is_empty() {
            String::new()
        } else {
            format!(" {}", escape_for_terminal(&self.operands))
        };

        let address = format_address(self.address);
        let bytes = self.render_bytes_field();
        let mnemonic_padded = format!(
            "{:<mnemonic_width$}",
            mnemonic,
            mnemonic_width = MNEMONIC_COLUMN_WIDTH
        );

        format!(
            "{}  {}  {}{}",
            style_address(&address, color_enabled),
            style_bytes(&bytes, color_enabled),
            style_mnemonic(&mnemonic_padded, &self.mnemonic, color_enabled),
            style_operands(&operands, color_enabled)
        )
    }

    fn render_pretty(&self, color_enabled: bool) -> StyledLine {
        let address_plain = format_address(self.address);
        let bytes_plain = self.render_bytes_field();
        let safe_mnemonic = escape_for_terminal(&self.mnemonic);
        let mnemonic_plain = format!(
            "{:<mnemonic_width$}",
            safe_mnemonic,
            mnemonic_width = MNEMONIC_COLUMN_WIDTH
        );
        let operands_plain = if self.operands.is_empty() {
            String::new()
        } else {
            format!(" {}", escape_for_terminal(&self.operands))
        };

        let plain = format!(
            "{}  {}  {}{}",
            address_plain, bytes_plain, mnemonic_plain, operands_plain
        );
        let styled = format!(
            "{}  {}  {}{}",
            style_address(&address_plain, color_enabled),
            style_bytes(&bytes_plain, color_enabled),
            style_mnemonic(&mnemonic_plain, &self.mnemonic, color_enabled),
            style_operands(&operands_plain, color_enabled)
        );

        StyledLine::styled(plain, styled)
    }

    fn render_bytes_field(&self) -> String {
        let mut bytes = String::with_capacity(BYTE_COLUMN_WIDTH + 2);
        for (index, byte) in self
            .bytes
            .iter()
            .take(MAX_RENDERED_INSTRUCTION_BYTES)
            .enumerate()
        {
            if index > 0 {
                bytes.push(' ');
            }
            let _ = write!(bytes, "{byte:02x}");
        }

        if self.bytes.len() > MAX_RENDERED_INSTRUCTION_BYTES {
            bytes.push_str(" …");
        }

        format!("{:<width$}", bytes, width = BYTE_COLUMN_WIDTH)
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

    let capstone = build_capstone(architecture, request.syntax)?;

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
            ("syntax".into(), request.syntax.display_name().into()),
            (
                "word-size".into(),
                if file.is_64() { "64-bit" } else { "32-bit" }.into(),
            ),
            ("entry".into(), format!("{:#x}", file.entry())),
            ("symbols".into(), request.symbols.join(", ")),
        ];

        if !request.sections.is_empty() {
            metadata.push(("filter".into(), request.sections.join(", ")));
        }

        return Ok(DisassemblyReport {
            target: path.display().to_string(),
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

        let instructions = disassemble_bytes(&capstone, data, section.address())
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
        ("syntax".into(), request.syntax.display_name().into()),
        (
            "word-size".into(),
            if file.is_64() { "64-bit" } else { "32-bit" }.into(),
        ),
        ("entry".into(), format!("{:#x}", file.entry())),
    ];

    if !request.sections.is_empty() {
        metadata.push(("filter".into(), request.sections.join(", ")));
    }

    Ok(DisassemblyReport {
        target: path.display().to_string(),
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
    let bytes = parse_hex_bytes(raw_hex)?;
    let capstone = build_capstone(architecture, request.syntax)?;
    let instructions = disassemble_bytes(&capstone, &bytes, request.base_address)
        .context("failed to disassemble raw bytes")?;

    Ok(DisassemblyReport {
        target: "<raw-hex>".into(),
        metadata: vec![
            ("architecture".into(), architecture.display_name().into()),
            (
                "base-address".into(),
                format!("{:#x}", request.base_address),
            ),
            ("syntax".into(), request.syntax.display_name().into()),
            ("byte-count".into(), bytes.len().to_string()),
        ],
        sections: vec![DisassembledSection {
            name: "raw".into(),
            address: request.base_address,
            size: bytes.len() as u64,
            labels: BTreeMap::new(),
            instructions,
        }],
    })
}

fn build_capstone(architecture: Architecture, syntax: Syntax) -> Result<Capstone> {
    let capstone = match architecture {
        Architecture::X86 => Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode32)
            .syntax(map_x86_syntax(syntax))
            .detail(false)
            .build(),
        Architecture::X86_64 => Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .syntax(map_x86_syntax(syntax))
            .detail(false)
            .build(),
        Architecture::Arm => Capstone::new()
            .arm()
            .mode(arch::arm::ArchMode::Arm)
            .detail(false)
            .build(),
        Architecture::Thumb => Capstone::new()
            .arm()
            .mode(arch::arm::ArchMode::Thumb)
            .detail(false)
            .build(),
        Architecture::Aarch64 => Capstone::new()
            .arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .detail(false)
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

fn disassemble_bytes(capstone: &Capstone, bytes: &[u8], address: u64) -> Result<Vec<Instruction>> {
    let instructions = capstone
        .disasm_all(bytes, address)
        .map_err(|error| anyhow!("capstone failed to decode bytes at {address:#x}: {error}"))?;

    Ok(instructions
        .iter()
        .map(|instruction| Instruction {
            address: instruction.address(),
            bytes: instruction.bytes().to_vec(),
            mnemonic: instruction.mnemonic().unwrap_or("<unknown>").to_owned(),
            operands: instruction.op_str().unwrap_or_default().to_owned(),
        })
        .collect())
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
        let start = symbol.address().saturating_sub(section.address()) as usize;
        let size = symbol.size() as usize;
        ensure!(
            start <= data.len() && start.saturating_add(size) <= data.len(),
            "symbol {} points outside its containing section",
            escape_for_terminal(name)
        );

        let symbol_bytes = &data[start..start + size];
        let instructions = disassemble_bytes(capstone, symbol_bytes, symbol.address())
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

fn render_section_box(section: &DisassembledSection, color_enabled: bool) -> String {
    let safe_name = escape_for_terminal(&section.name);
    let mut lines = vec![StyledLine::styled(
        format!(
            "addr {}  •  size {}  •  instructions {}",
            format_address(section.address),
            format!("{:#x}", section.size),
            section.instructions.len()
        ),
        format!(
            "{} {}  {}  {} {}  {}  {} {}",
            style_meta_key("addr", color_enabled),
            style_address(&format_address(section.address), color_enabled),
            style_separator("•", color_enabled),
            style_meta_key("size", color_enabled),
            style_number(&format!("{:#x}", section.size), color_enabled),
            style_separator("•", color_enabled),
            style_meta_key("instructions", color_enabled),
            style_number(&section.instructions.len().to_string(), color_enabled)
        ),
    )];

    if !section.instructions.is_empty() || !section.labels.is_empty() {
        lines.push(StyledLine::plain(String::new()));
    }

    let mut emitted_addresses = BTreeSet::new();
    for instruction in &section.instructions {
        if let Some(labels) = section.labels.get(&instruction.address) {
            for label in labels {
                let safe_label = escape_for_terminal(label);
                lines.push(StyledLine::styled(
                    format!("• {}", safe_label),
                    format!(
                        "{} {}",
                        style_separator("•", color_enabled),
                        style_label(&safe_label, color_enabled)
                    ),
                ));
            }
        }

        lines.push(instruction.render_pretty(color_enabled));
        emitted_addresses.insert(instruction.address);
    }

    if section.instructions.is_empty() {
        lines.push(StyledLine::styled(
            "<no instructions decoded>".into(),
            style_note("<no instructions decoded>", color_enabled),
        ));
    }

    for (address, labels) in &section.labels {
        if emitted_addresses.contains(address) {
            continue;
        }

        for label in labels {
            let safe_label = escape_for_terminal(label);
            lines.push(StyledLine::styled(
                format!("orphan label {address:#018x} {}", safe_label),
                format!(
                    "{} {} {} {}",
                    style_note("orphan label", color_enabled),
                    style_address(&format_address(*address), color_enabled),
                    style_separator("→", color_enabled),
                    style_label(&safe_label, color_enabled)
                ),
            ));
        }
    }

    render_box(
        &format!("section {safe_name}"),
        &format!(
            "{} {}",
            style_box_title("SECTION", color_enabled),
            style_section_name(&safe_name, color_enabled)
        ),
        &lines,
    )
}

fn render_box(title_plain: &str, title_styled: &str, lines: &[StyledLine]) -> String {
    let inner_width = lines
        .iter()
        .map(|line| visible_width(&line.plain))
        .max()
        .unwrap_or_default()
        .max(visible_width(title_plain) + 1);

    let title_width = visible_width(title_plain);
    let fill = inner_width.saturating_sub(title_width);

    let mut output = String::new();
    let _ = writeln!(output, "╭─ {}{}╮", title_styled, "─".repeat(fill));
    for line in lines {
        let padding = inner_width.saturating_sub(visible_width(&line.plain));
        let _ = writeln!(output, "│ {}{} │", line.styled, " ".repeat(padding));
    }
    let _ = write!(output, "╰{}╯", "─".repeat(inner_width + 2));
    output
}

fn styled_key_value_line(key: &str, value: String, color_enabled: bool) -> StyledLine {
    let padded_key = pad_display_right(key, 12);
    let plain = format!("{} {}", padded_key, value);
    let styled = format!(
        "{} {}",
        style_meta_key(&padded_key, color_enabled),
        style_meta_value(&value, color_enabled)
    );

    StyledLine::styled(plain, styled)
}

fn format_address(address: u64) -> String {
    format!("{address:#018x}")
}

fn visible_width(value: &str) -> usize {
    UnicodeWidthStr::width(value)
}

fn pad_display_right(value: &str, width: usize) -> String {
    let current_width = visible_width(value);
    if current_width >= width {
        value.to_owned()
    } else {
        format!("{}{}", value, " ".repeat(width - current_width))
    }
}

fn style_text(text: &str, color_enabled: bool, codes: &[&str]) -> String {
    if color_enabled {
        format!("\x1b[{}m{}\x1b[0m", codes.join(";"), text)
    } else {
        text.to_owned()
    }
}

fn style_box_title(text: &str, color_enabled: bool) -> String {
    style_text(text, color_enabled, &["1", "97"])
}

fn style_section_name(text: &str, color_enabled: bool) -> String {
    style_text(text, color_enabled, &["1", "95"])
}

fn style_meta_key(text: &str, color_enabled: bool) -> String {
    style_text(text, color_enabled, &["1", "90"])
}

fn style_meta_value(text: &str, color_enabled: bool) -> String {
    style_text(text, color_enabled, &["97"])
}

fn style_separator(text: &str, color_enabled: bool) -> String {
    style_text(text, color_enabled, &["90"])
}

fn style_note(text: &str, color_enabled: bool) -> String {
    style_text(text, color_enabled, &["3", "90"])
}

fn style_label(text: &str, color_enabled: bool) -> String {
    style_text(text, color_enabled, &["1", "93"])
}

fn style_address(text: &str, color_enabled: bool) -> String {
    style_text(text, color_enabled, &["1", "96"])
}

fn style_bytes(text: &str, color_enabled: bool) -> String {
    style_text(text, color_enabled, &["90"])
}

fn style_number(text: &str, color_enabled: bool) -> String {
    style_text(text, color_enabled, &["95"])
}

fn style_mnemonic(field: &str, mnemonic: &str, color_enabled: bool) -> String {
    let category = classify_mnemonic(mnemonic);
    let codes = match category {
        MnemonicCategory::ControlFlow => &["1", "91"][..],
        MnemonicCategory::Move => &["1", "94"][..],
        MnemonicCategory::Stack => &["1", "93"][..],
        MnemonicCategory::Compare => &["1", "95"][..],
        MnemonicCategory::Arithmetic => &["1", "92"][..],
        MnemonicCategory::Logic => &["32"][..],
        MnemonicCategory::Nop => &["3", "90"][..],
        MnemonicCategory::Other => &["1", "97"][..],
    };
    style_text(field, color_enabled, codes)
}

fn style_operands(operands: &str, color_enabled: bool) -> String {
    debug_assert!(
        operands.is_ascii(),
        "escaped operand rendering expects ASCII-only input"
    );

    let mut output = String::with_capacity(operands.len() + 16);
    let bytes = operands.as_bytes();
    let mut index = 0;

    while index < bytes.len() {
        let current = bytes[index] as char;

        if current.is_whitespace() {
            output.push(current);
            index += 1;
            continue;
        }

        if let Some(end) = read_special_operand_token(bytes, index) {
            let token = &operands[index..end];
            output.push_str(&style_operand_token(&token, color_enabled));
            index = end;
            continue;
        }

        if is_operand_separator_byte(bytes[index]) {
            output.push_str(&style_separator(&current.to_string(), color_enabled));
            index += 1;
            continue;
        }

        let start = index;
        while index < bytes.len()
            && !bytes[index].is_ascii_whitespace()
            && !is_operand_separator_byte(bytes[index])
        {
            index += 1;
        }

        let token = &operands[start..index];
        output.push_str(&style_operand_token(&token, color_enabled));
    }

    output
}

fn read_special_operand_token(bytes: &[u8], start: usize) -> Option<usize> {
    let current = *bytes.get(start)? as char;
    let next = bytes.get(start + 1).copied().map(char::from);

    if current == '\\' {
        return read_escaped_operand_token(bytes, start);
    }

    if matches!(current, '$' | '#') && next.is_some_and(is_signed_numeric_start) {
        return Some(read_numeric_body_end(bytes, start + 1));
    }

    if is_signed_numeric_start(current)
        && (start == 0 || previous_allows_numeric_sign(bytes[start - 1] as char))
    {
        return Some(read_numeric_body_end(bytes, start));
    }

    None
}

fn read_escaped_operand_token(bytes: &[u8], start: usize) -> Option<usize> {
    let next = bytes.get(start + 1).copied().map(char::from)?;

    if matches!(next, 'n' | 'r' | 't' | '\\' | '0') {
        return Some((start + 2).min(bytes.len()));
    }

    if next == 'u' && bytes.get(start + 2) == Some(&b'{') {
        let mut index = start + 3;
        while index < bytes.len() {
            if bytes[index] == b'}' {
                return Some(index + 1);
            }
            index += 1;
        }
    }

    None
}

fn read_numeric_body_end(bytes: &[u8], start: usize) -> usize {
    let mut index = start;

    if bytes.get(index) == Some(&b'-') {
        index += 1;
    }

    while index < bytes.len() && is_numeric_body_char(bytes[index] as char) {
        index += 1;
    }

    index
}

fn is_signed_numeric_start(character: char) -> bool {
    character == '-' || character.is_ascii_digit()
}

fn previous_allows_numeric_sign(character: char) -> bool {
    character.is_whitespace() || matches!(character, ',' | '[' | '(' | '{' | '+' | '=')
}

fn is_numeric_body_char(character: char) -> bool {
    character.is_ascii_hexdigit() || matches!(character, 'x' | 'X')
}

fn is_operand_separator(character: char) -> bool {
    matches!(
        character,
        ',' | '[' | ']' | '(' | ')' | '{' | '}' | '+' | '-' | '*' | '<' | '>' | ':' | '!' | '='
    )
}

fn is_operand_separator_byte(byte: u8) -> bool {
    is_operand_separator(byte as char)
}

fn style_operand_token(token: &str, color_enabled: bool) -> String {
    if token.is_empty() {
        return String::new();
    }

    let register_like = token
        .trim_start_matches('%')
        .trim_end_matches(',')
        .to_ascii_lowercase();
    let size_like = token
        .trim_start_matches(['#', '$', '%'])
        .trim_end_matches(',')
        .to_ascii_lowercase();

    if is_numeric_token(token) {
        style_number(token, color_enabled)
    } else if is_register_token(&register_like) {
        style_text(token, color_enabled, &["1", "96"])
    } else if is_size_token(&size_like) {
        style_text(token, color_enabled, &["1", "94"])
    } else {
        style_text(token, color_enabled, &["97"])
    }
}

fn is_numeric_token(token: &str) -> bool {
    let trimmed = token
        .trim_start_matches(['#', '$'])
        .trim_start_matches(['-', '+']);
    if trimmed.is_empty() {
        return false;
    }

    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        return !hex.is_empty() && hex.chars().all(|character| character.is_ascii_hexdigit());
    }

    trimmed.chars().all(|character| character.is_ascii_digit())
}

fn is_register_token(token: &str) -> bool {
    matches!(
        token,
        "rax"
            | "rbx"
            | "rcx"
            | "rdx"
            | "rsi"
            | "rdi"
            | "rbp"
            | "rsp"
            | "rip"
            | "eax"
            | "ebx"
            | "ecx"
            | "edx"
            | "esi"
            | "edi"
            | "ebp"
            | "esp"
            | "ax"
            | "bx"
            | "cx"
            | "dx"
            | "si"
            | "di"
            | "bp"
            | "sp"
            | "al"
            | "ah"
            | "bl"
            | "bh"
            | "cl"
            | "ch"
            | "dl"
            | "dh"
            | "cs"
            | "ds"
            | "es"
            | "fs"
            | "gs"
            | "ss"
            | "pc"
            | "lr"
            | "fp"
            | "ip"
            | "xzr"
            | "wzr"
            | "nzcv"
    ) || token.strip_prefix('r').is_some_and(|suffix| {
        !suffix.is_empty() && suffix.chars().all(|character| character.is_ascii_digit())
    }) || token.strip_prefix('x').is_some_and(|suffix| {
        !suffix.is_empty() && suffix.chars().all(|character| character.is_ascii_digit())
    }) || token.strip_prefix('w').is_some_and(|suffix| {
        !suffix.is_empty() && suffix.chars().all(|character| character.is_ascii_digit())
    }) || token.strip_prefix('v').is_some_and(|suffix| {
        !suffix.is_empty() && suffix.chars().all(|character| character.is_ascii_digit())
    }) || token.strip_prefix("xmm").is_some_and(|suffix| {
        !suffix.is_empty() && suffix.chars().all(|character| character.is_ascii_digit())
    }) || token.strip_prefix("ymm").is_some_and(|suffix| {
        !suffix.is_empty() && suffix.chars().all(|character| character.is_ascii_digit())
    }) || token.strip_prefix("zmm").is_some_and(|suffix| {
        !suffix.is_empty() && suffix.chars().all(|character| character.is_ascii_digit())
    })
}

fn is_size_token(token: &str) -> bool {
    matches!(
        token,
        "byte" | "word" | "dword" | "qword" | "xword" | "xmmword" | "ymmword" | "zmmword" | "ptr"
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MnemonicCategory {
    ControlFlow,
    Move,
    Stack,
    Compare,
    Arithmetic,
    Logic,
    Nop,
    Other,
}

fn classify_mnemonic(mnemonic: &str) -> MnemonicCategory {
    let mnemonic = mnemonic.trim().to_ascii_lowercase();

    if mnemonic == "nop" {
        MnemonicCategory::Nop
    } else if mnemonic.starts_with('j')
        || matches!(
            mnemonic.as_str(),
            "call" | "ret" | "retq" | "b" | "bl" | "blr" | "br"
        )
        || mnemonic.starts_with("cb")
        || mnemonic.starts_with("tb")
        || mnemonic.starts_with("b.")
    {
        MnemonicCategory::ControlFlow
    } else if mnemonic.starts_with("push")
        || mnemonic.starts_with("pop")
        || mnemonic == "enter"
        || mnemonic == "leave"
    {
        MnemonicCategory::Stack
    } else if mnemonic.starts_with("mov")
        || mnemonic == "lea"
        || mnemonic.starts_with("ldr")
        || mnemonic.starts_with("str")
        || mnemonic.starts_with("ldp")
        || mnemonic.starts_with("stp")
        || mnemonic.starts_with("adr")
    {
        MnemonicCategory::Move
    } else if mnemonic.starts_with("cmp") || mnemonic == "test" || mnemonic == "tst" {
        MnemonicCategory::Compare
    } else if mnemonic.starts_with("add")
        || mnemonic.starts_with("sub")
        || mnemonic.starts_with("mul")
        || mnemonic.starts_with("imul")
        || mnemonic.starts_with("div")
        || mnemonic.starts_with("idiv")
        || mnemonic.starts_with("inc")
        || mnemonic.starts_with("dec")
        || mnemonic.starts_with("neg")
    {
        MnemonicCategory::Arithmetic
    } else if mnemonic.starts_with("and")
        || mnemonic.starts_with("or")
        || mnemonic.starts_with("xor")
        || mnemonic.starts_with("sh")
        || mnemonic.starts_with("sa")
        || mnemonic.starts_with("ro")
        || mnemonic.starts_with("not")
    {
        MnemonicCategory::Logic
    } else {
        MnemonicCategory::Other
    }
}

fn parse_hex_bytes(raw: &str) -> Result<Vec<u8>> {
    let mut nybbles = Vec::with_capacity(raw.len());
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
    for (index, pair) in nybbles.chunks_exact(2).enumerate() {
        let high = decode_hex_nybble(pair[0]).expect("validated high nybble");
        let low = decode_hex_nybble(pair[1]).expect("validated low nybble");
        let _ = index;
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

fn escape_for_terminal(raw: &str) -> String {
    raw.chars()
        .flat_map(|character| character.escape_default())
        .collect()
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
        Instruction, MAX_RAW_INPUT_BYTES, RenderOptions, Syntax, disassemble, escape_for_terminal,
        parse_hex_bytes, render_box, render_section_box, should_disassemble_section,
        style_operands,
    };
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
                },
                Instruction {
                    address: 0x1001,
                    bytes: vec![0x48, 0x89, 0xe5],
                    mnemonic: "mov".into(),
                    operands: "rbp, rsp".into(),
                },
                Instruction {
                    address: 0x1004,
                    bytes: vec![0x5d],
                    mnemonic: "pop".into(),
                    operands: "rbp".into(),
                },
                Instruction {
                    address: 0x1005,
                    bytes: vec![0xc3],
                    mnemonic: "ret".into(),
                    operands: String::new(),
                },
            ],
        }
    }

    fn sample_report() -> DisassemblyReport {
        DisassemblyReport {
            target: "<test>".into(),
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
                    },
                    Instruction {
                        address: 0x1001,
                        bytes: vec![0xc3],
                        mnemonic: "ret".into(),
                        operands: String::new(),
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
                super::styled_key_value_line("target", "<raw-hex>".into(), false),
                super::styled_key_value_line("architecture", "x86_64".into(), false),
                super::styled_key_value_line("byte-count", "6".into(), false),
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
        let styled = style_operands(" %xmm1, x2, wzr, rax ", false);
        assert!(styled.contains("%xmm1"));
        assert!(styled.contains("x2"));
        assert!(styled.contains("wzr"));
        assert!(styled.contains("rax"));
    }

    #[test]
    fn rejects_raw_hex_input_over_limit() {
        let too_large = "aa".repeat(MAX_RAW_INPUT_BYTES + 1);
        let error = parse_hex_bytes(&too_large).unwrap_err().to_string();
        assert!(error.contains("raw hex input exceeds maximum supported size"));
    }
}
