use std::collections::HashSet;
use std::fmt::{self, Display, Write as _};

use unicode_width::UnicodeWidthStr;

use crate::types::{DisassembledSection, DisassemblyReport, Instruction, RenderOptions};

const MAX_RENDERED_INSTRUCTION_BYTES: usize = 16;
const BYTE_COLUMN_WIDTH: usize = MAX_RENDERED_INSTRUCTION_BYTES * 3;
const MNEMONIC_COLUMN_WIDTH: usize = 12;

#[derive(Debug)]
pub(crate) struct StyledLine {
    pub(crate) plain: String,
    pub(crate) styled: String,
}

impl StyledLine {
    pub(crate) fn plain(text: String) -> Self {
        Self {
            plain: text.clone(),
            styled: text,
        }
    }

    pub(crate) fn styled(plain: String, styled: String) -> Self {
        Self { plain, styled }
    }
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

            let mut emitted_addresses = HashSet::with_capacity(section.instructions.len());
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

    pub(crate) fn render_pretty(&self, color_enabled: bool) -> StyledLine {
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

        if bytes.len() < BYTE_COLUMN_WIDTH {
            bytes.reserve(BYTE_COLUMN_WIDTH - bytes.len());
            while bytes.len() < BYTE_COLUMN_WIDTH {
                bytes.push(' ');
            }
        }

        bytes
    }
}

pub(crate) fn render_section_box(section: &DisassembledSection, color_enabled: bool) -> String {
    let safe_name = escape_for_terminal(&section.name);
    let section_size = format!("{:#x}", section.size);
    let mut lines = vec![StyledLine::styled(
        format!(
            "addr {}  •  size {}  •  instructions {}",
            format_address(section.address),
            section_size,
            section.instructions.len()
        ),
        format!(
            "{} {}  {}  {} {}  {}  {} {}",
            style_meta_key("addr", color_enabled),
            style_address(&format_address(section.address), color_enabled),
            style_separator("•", color_enabled),
            style_meta_key("size", color_enabled),
            style_number(&section_size, color_enabled),
            style_separator("•", color_enabled),
            style_meta_key("instructions", color_enabled),
            style_number(&section.instructions.len().to_string(), color_enabled)
        ),
    )];

    if !section.instructions.is_empty() || !section.labels.is_empty() {
        lines.push(StyledLine::plain(String::new()));
    }

    let mut emitted_addresses = HashSet::with_capacity(section.instructions.len());
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

pub(crate) fn render_box(title_plain: &str, title_styled: &str, lines: &[StyledLine]) -> String {
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
        let _ = write!(output, "│ {}", line.styled);
        for _ in 0..padding {
            output.push(' ');
        }
        let _ = writeln!(output, " │");
    }
    let _ = write!(output, "╰{}╯", "─".repeat(inner_width + 2));
    output
}

pub(crate) fn styled_key_value_line(key: &str, value: String, color_enabled: bool) -> StyledLine {
    let padded_key = pad_display_right(key, 12);
    let plain = format!("{} {}", padded_key, value);
    let styled = format!(
        "{} {}",
        style_meta_key(&padded_key, color_enabled),
        style_meta_value(&value, color_enabled)
    );

    StyledLine::styled(plain, styled)
}

pub(crate) fn format_address(address: u64) -> String {
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

pub(crate) fn style_text(text: &str, color_enabled: bool, codes: &[&str]) -> String {
    if color_enabled {
        format!("\x1b[{}m{}\x1b[0m", codes.join(";"), text)
    } else {
        text.to_owned()
    }
}

pub(crate) fn style_box_title(text: &str, color_enabled: bool) -> String {
    style_text(text, color_enabled, &["1", "97"])
}

pub(crate) fn style_section_name(text: &str, color_enabled: bool) -> String {
    style_text(text, color_enabled, &["1", "95"])
}

pub(crate) fn style_meta_key(text: &str, color_enabled: bool) -> String {
    style_text(text, color_enabled, &["1", "90"])
}

pub(crate) fn style_meta_value(text: &str, color_enabled: bool) -> String {
    style_text(text, color_enabled, &["97"])
}

pub(crate) fn style_separator(text: &str, color_enabled: bool) -> String {
    style_text(text, color_enabled, &["90"])
}

pub(crate) fn style_note(text: &str, color_enabled: bool) -> String {
    style_text(text, color_enabled, &["3", "90"])
}

pub(crate) fn style_label(text: &str, color_enabled: bool) -> String {
    style_text(text, color_enabled, &["1", "93"])
}

pub(crate) fn style_address(text: &str, color_enabled: bool) -> String {
    style_text(text, color_enabled, &["1", "96"])
}

fn style_bytes(text: &str, color_enabled: bool) -> String {
    style_text(text, color_enabled, &["90"])
}

pub(crate) fn style_number(text: &str, color_enabled: bool) -> String {
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

pub(crate) fn style_operands(operands: &str, color_enabled: bool) -> String {
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
            output.push_str(&style_operand_token(token, color_enabled));
            index = end;
            continue;
        }

        if is_operand_separator_byte(bytes[index]) {
            output.push_str(&style_separator(&operands[index..index + 1], color_enabled));
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
        output.push_str(&style_operand_token(token, color_enabled));
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

    let normalized = token
        .trim_start_matches(['#', '$', '%'])
        .trim_end_matches(',');

    if is_numeric_token(token) {
        style_number(token, color_enabled)
    } else if is_register_token(normalized) {
        style_text(token, color_enabled, &["1", "96"])
    } else if is_size_token(normalized) {
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
    matches_exact_ascii_case_any(
        token,
        &[
            "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip", "eax", "ebx", "ecx",
            "edx", "esi", "edi", "ebp", "esp", "ax", "bx", "cx", "dx", "si", "di", "bp", "sp",
            "wsp", "al", "ah", "bl", "bh", "cl", "ch", "dl", "dh", "cs", "ds", "es", "fs", "gs",
            "ss", "pc", "lr", "fp", "ip", "xzr", "wzr", "nzcv", "fpcr", "fpsr", "daif",
        ],
    ) || matches_prefixed_digits(token, "r")
        || matches_prefixed_digits(token, "x")
        || matches_prefixed_digits(token, "w")
        || matches_prefixed_digits(token, "v")
        || matches_prefixed_digits(token, "xmm")
        || matches_prefixed_digits(token, "ymm")
        || matches_prefixed_digits(token, "zmm")
}

fn is_size_token(token: &str) -> bool {
    matches_exact_ascii_case_any(
        token,
        &[
            "byte", "word", "dword", "qword", "xword", "xmmword", "ymmword", "zmmword", "ptr",
        ],
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
    let mnemonic = mnemonic.trim();

    if mnemonic.eq_ignore_ascii_case("nop") {
        MnemonicCategory::Nop
    } else if starts_with_ignore_ascii_case(mnemonic, "j")
        || matches_exact_ascii_case_any(mnemonic, &["call", "ret", "retq", "b", "bl", "blr", "br"])
        || starts_with_ignore_ascii_case(mnemonic, "cb")
        || starts_with_ignore_ascii_case(mnemonic, "tb")
        || starts_with_ignore_ascii_case(mnemonic, "b.")
    {
        MnemonicCategory::ControlFlow
    } else if starts_with_ignore_ascii_case(mnemonic, "push")
        || starts_with_ignore_ascii_case(mnemonic, "pop")
        || mnemonic.eq_ignore_ascii_case("enter")
        || mnemonic.eq_ignore_ascii_case("leave")
    {
        MnemonicCategory::Stack
    } else if starts_with_ignore_ascii_case(mnemonic, "mov")
        || mnemonic.eq_ignore_ascii_case("lea")
        || starts_with_ignore_ascii_case(mnemonic, "ldr")
        || starts_with_ignore_ascii_case(mnemonic, "str")
        || starts_with_ignore_ascii_case(mnemonic, "ldp")
        || starts_with_ignore_ascii_case(mnemonic, "stp")
        || starts_with_ignore_ascii_case(mnemonic, "adr")
    {
        MnemonicCategory::Move
    } else if starts_with_ignore_ascii_case(mnemonic, "cmp")
        || mnemonic.eq_ignore_ascii_case("test")
        || mnemonic.eq_ignore_ascii_case("tst")
    {
        MnemonicCategory::Compare
    } else if starts_with_ignore_ascii_case(mnemonic, "add")
        || starts_with_ignore_ascii_case(mnemonic, "sub")
        || starts_with_ignore_ascii_case(mnemonic, "mul")
        || starts_with_ignore_ascii_case(mnemonic, "imul")
        || starts_with_ignore_ascii_case(mnemonic, "div")
        || starts_with_ignore_ascii_case(mnemonic, "idiv")
        || starts_with_ignore_ascii_case(mnemonic, "inc")
        || starts_with_ignore_ascii_case(mnemonic, "dec")
        || starts_with_ignore_ascii_case(mnemonic, "neg")
    {
        MnemonicCategory::Arithmetic
    } else if starts_with_ignore_ascii_case(mnemonic, "and")
        || starts_with_ignore_ascii_case(mnemonic, "or")
        || starts_with_ignore_ascii_case(mnemonic, "xor")
        || starts_with_ignore_ascii_case(mnemonic, "sh")
        || starts_with_ignore_ascii_case(mnemonic, "sa")
        || starts_with_ignore_ascii_case(mnemonic, "ro")
        || starts_with_ignore_ascii_case(mnemonic, "not")
    {
        MnemonicCategory::Logic
    } else {
        MnemonicCategory::Other
    }
}

fn matches_exact_ascii_case_any(token: &str, candidates: &[&str]) -> bool {
    candidates
        .iter()
        .any(|candidate| token.eq_ignore_ascii_case(candidate))
}

fn matches_prefixed_digits(token: &str, prefix: &str) -> bool {
    strip_ascii_case_prefix(token, prefix).is_some_and(|suffix| {
        !suffix.is_empty() && suffix.chars().all(|character| character.is_ascii_digit())
    })
}

fn starts_with_ignore_ascii_case(value: &str, prefix: &str) -> bool {
    strip_ascii_case_prefix(value, prefix).is_some()
}

fn strip_ascii_case_prefix<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    let head = value.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| value.get(prefix.len()..))
        .flatten()
}

pub(crate) fn escape_for_terminal(raw: &str) -> String {
    raw.chars()
        .flat_map(|character| character.escape_default())
        .collect()
}
