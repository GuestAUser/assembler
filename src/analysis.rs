use std::fmt::Write as _;

use unicode_width::UnicodeWidthStr;

use crate::disasm::{
    Architecture, DisassembledSection, DisassemblyReport, Instruction, OperandAccess,
    OperandDetail, RenderOptions,
};

const FRAME_SETUP_SCAN_LIMIT: usize = 16;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnalysisReport {
    architecture: Architecture,
    findings: Vec<Finding>,
    notes: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Finding {
    pub kind: FindingKind,
    pub severity: Severity,
    pub section: String,
    pub address: u64,
    pub rationale: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum FindingKind {
    PotentialStackBufferWriteRisk,
    PossibleOutOfBoundsLocalWrite,
    SuspiciousCopyLoop,
    UnsafeStackFrameWrite,
    StackPointerFramePointerAnomaly,
    IndirectWriteRisk,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Severity {
    Low,
    Medium,
    High,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FrameBase {
    Rbp,
    Rsp,
    Ebp,
    Esp,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct FrameState {
    base: Option<FrameBase>,
    size: Option<i64>,
    frame_pointer_established: bool,
}

#[derive(Clone, Debug)]
struct LoopEvidence {
    start: usize,
    end: usize,
    target: u64,
    counter_register: Option<String>,
    bound: Option<i64>,
}

#[derive(Clone, Debug)]
struct MemoryOperandRef<'a> {
    base: Option<&'a str>,
    index: Option<&'a str>,
    disp: i64,
    access: Option<OperandAccess>,
    size: u8,
}

pub fn analyze(report: &DisassemblyReport) -> AnalysisReport {
    let mut findings = Vec::new();
    let mut notes = Vec::new();

    if !matches!(
        report.architecture,
        Architecture::X86 | Architecture::X86_64
    ) {
        notes.push(format!(
            "No semantic risk analyzer is currently implemented for {} disassembly.",
            report.architecture.display_name()
        ));
        return AnalysisReport {
            architecture: report.architecture,
            findings,
            notes,
        };
    }

    for section in &report.sections {
        analyze_section(section, &mut findings);
    }

    if findings.is_empty() {
        notes.push(
            "No supported memory-safety findings were identified from the local disassembly evidence."
                .into(),
        );
    }

    findings.sort_by_key(|finding| (finding.address, finding.kind, finding.severity));

    AnalysisReport {
        architecture: report.architecture,
        findings,
        notes,
    }
}

impl AnalysisReport {
    pub fn render(&self, options: &RenderOptions) -> String {
        if options.is_pretty() {
            self.render_pretty(options.color_enabled())
        } else {
            self.render_plain(options.color_enabled())
        }
    }

    fn render_plain(&self, color_enabled: bool) -> String {
        let mut output = String::new();
        let _ = writeln!(output);
        let _ = writeln!(
            output,
            "{}: {}",
            style_meta_key("analysis     ", color_enabled),
            style_meta_value("enabled", color_enabled)
        );
        let _ = writeln!(
            output,
            "{}: {}",
            style_meta_key("architecture", color_enabled),
            style_meta_value(self.architecture.display_name(), color_enabled)
        );
        let _ = writeln!(
            output,
            "{}: {}",
            style_meta_key("findings     ", color_enabled),
            style_meta_value(&self.findings.len().to_string(), color_enabled)
        );

        for note in &self.notes {
            let _ = writeln!(
                output,
                "{}: {}",
                style_meta_key("note         ", color_enabled),
                style_note(&escape_for_terminal(note), color_enabled)
            );
        }

        for finding in &self.findings {
            let _ = writeln!(output);
            let _ = writeln!(
                output,
                "[{}] {} @ {} ({})",
                style_severity(finding.severity.label(), finding.severity, color_enabled),
                style_kind(finding.kind.label(), color_enabled),
                style_address(&format_address(finding.address), color_enabled),
                style_meta_value(&escape_for_terminal(&finding.section), color_enabled)
            );
            let _ = writeln!(
                output,
                "  {}",
                style_meta_value(&escape_for_terminal(&finding.rationale), color_enabled)
            );
        }

        output
    }

    fn render_pretty(&self, color_enabled: bool) -> String {
        let mut lines = vec![StyledLine::styled(
            format!("architecture {}", self.architecture.display_name()),
            format!(
                "{} {}",
                style_meta_key("architecture", color_enabled),
                style_meta_value(self.architecture.display_name(), color_enabled)
            ),
        )];
        lines.push(StyledLine::styled(
            format!("findings {}", self.findings.len()),
            format!(
                "{} {}",
                style_meta_key("findings", color_enabled),
                style_meta_value(&self.findings.len().to_string(), color_enabled)
            ),
        ));

        for note in &self.notes {
            lines.push(StyledLine::styled(
                format!("note {}", escape_for_terminal(note)),
                format!(
                    "{} {}",
                    style_meta_key("note", color_enabled),
                    style_note(&escape_for_terminal(note), color_enabled)
                ),
            ));
        }

        for finding in &self.findings {
            lines.push(StyledLine::plain(String::new()));
            let heading_plain = format!(
                "{} {} {} {}",
                finding.severity.label(),
                finding.kind.label(),
                format_address(finding.address),
                finding.section
            );
            let heading_styled = format!(
                "{} {} {} {}",
                style_severity(finding.severity.label(), finding.severity, color_enabled),
                style_kind(finding.kind.label(), color_enabled),
                style_address(&format_address(finding.address), color_enabled),
                style_meta_value(&escape_for_terminal(&finding.section), color_enabled)
            );
            lines.push(StyledLine::styled(heading_plain, heading_styled));
            lines.push(StyledLine::styled(
                escape_for_terminal(&finding.rationale),
                style_meta_value(&escape_for_terminal(&finding.rationale), color_enabled),
            ));
        }

        let mut rendered = render_box(
            "analysis",
            &style_box_title("ANALYSIS", color_enabled),
            &lines,
        );
        rendered.push('\n');
        rendered
    }
}

fn analyze_section(section: &DisassembledSection, findings: &mut Vec<Finding>) {
    let frame = detect_frame_state(section);

    for instruction in &section.instructions {
        analyze_instruction(section, instruction, frame, findings);
    }

    for loop_evidence in detect_loops(section) {
        analyze_loop(section, frame, &loop_evidence, findings);
    }
}

fn analyze_instruction(
    section: &DisassembledSection,
    instruction: &Instruction,
    frame: FrameState,
    findings: &mut Vec<Finding>,
) {
    for memory in memory_writes(instruction) {
        if let Some(reason) = unsafe_frame_write_reason(frame, &memory) {
            push_finding(
                findings,
                Finding {
                    kind: FindingKind::UnsafeStackFrameWrite,
                    severity: Severity::Medium,
                    section: section.name.clone(),
                    address: instruction.address,
                    rationale: reason,
                },
            );
        }

        if let Some(reason) = out_of_bounds_stack_write_reason(frame, &memory) {
            push_finding(
                findings,
                Finding {
                    kind: FindingKind::PossibleOutOfBoundsLocalWrite,
                    severity: Severity::High,
                    section: section.name.clone(),
                    address: instruction.address,
                    rationale: reason,
                },
            );
        }

        if let Some(reason) = stack_pointer_anomaly_reason(frame, &memory) {
            push_finding(
                findings,
                Finding {
                    kind: FindingKind::StackPointerFramePointerAnomaly,
                    severity: Severity::Medium,
                    section: section.name.clone(),
                    address: instruction.address,
                    rationale: reason,
                },
            );
        }

        if is_indirect_non_stack_write(&memory) {
            push_finding(
                findings,
                Finding {
                    kind: FindingKind::IndirectWriteRisk,
                    severity: Severity::Low,
                    section: section.name.clone(),
                    address: instruction.address,
                    rationale: format!(
                        "Instruction performs a memory write through computed pointer base {}{}; local bounds are not recoverable from this disassembly alone.",
                        memory.base.unwrap_or("<unknown>"),
                        memory
                            .index
                            .map(|index| format!(" with index {index}"))
                            .unwrap_or_default()
                    ),
                },
            );
        }
    }
}

fn analyze_loop(
    section: &DisassembledSection,
    frame: FrameState,
    loop_evidence: &LoopEvidence,
    findings: &mut Vec<Finding>,
) {
    let body = &section.instructions[loop_evidence.start..=loop_evidence.end];
    let mut saw_suspicious_copy = false;

    for instruction in body {
        for memory in memory_writes(instruction) {
            if let Some(index) = memory.index {
                if is_stack_base(memory.base) {
                    let capacity = estimate_stack_capacity(frame, &memory);
                    if let (Some(bound), Some(capacity), true) = (
                        loop_evidence.bound,
                        capacity,
                        loop_bound_matches_write_progress(loop_evidence, &memory),
                    ) {
                        if bound > capacity {
                            push_finding(
                                findings,
                                Finding {
                                    kind: FindingKind::PossibleOutOfBoundsLocalWrite,
                                    severity: Severity::High,
                                    section: section.name.clone(),
                                    address: instruction.address,
                                    rationale: format!(
                                        "Loop writes stack-local memory through index register {index}, and the same register is compared against immediate bound {bound}; that bound exceeds the inferred local capacity from displacement {:+#x}, which is only {capacity} bytes.",
                                        memory.disp
                                    ),
                                },
                            );
                            push_finding(
                                findings,
                                Finding {
                                    kind: FindingKind::PotentialStackBufferWriteRisk,
                                    severity: Severity::High,
                                    section: section.name.clone(),
                                    address: instruction.address,
                                    rationale: format!(
                                        "A backward branch to {:#x} drives repeated indexed writes into stack-local memory, and the compared progression register exceeds the inferred local capacity.",
                                        loop_evidence.target
                                    ),
                                },
                            );
                        }
                    } else if frame_supports_stack_capacity(frame, &memory) {
                        push_finding(
                            findings,
                            Finding {
                                kind: FindingKind::PotentialStackBufferWriteRisk,
                                severity: Severity::Medium,
                                section: section.name.clone(),
                                address: instruction.address,
                                rationale: format!(
                                    "Backward branch to {:#x} repeatedly writes indexed stack-local memory via {index}, but no local bound tied to the destination size was recovered.",
                                    loop_evidence.target
                                ),
                            },
                        );
                    }
                }

                saw_suspicious_copy = true;
            }
        }
    }

    if saw_suspicious_copy {
        push_finding(
            findings,
            Finding {
                kind: FindingKind::SuspiciousCopyLoop,
                severity: Severity::Medium,
                section: section.name.clone(),
                address: section.instructions[loop_evidence.end].address,
                rationale: match (&loop_evidence.counter_register, loop_evidence.bound) {
                    (Some(register), Some(bound))
                        if body.iter().flat_map(memory_writes).any(|memory| {
                            memory.index == Some(register.as_str())
                                || memory.base == Some(register.as_str())
                        }) =>
                    {
                        format!(
                            "Loop branches backward to {:#x} and repeatedly writes memory while progression register {register} is compared against immediate bound {bound}; destination size evidence remains weaker than the write progression.",
                            loop_evidence.target
                        )
                    }
                    _ => format!(
                        "Loop branches backward to {:#x} and repeatedly writes memory through computed addressing, but a strong destination bound was not recovered.",
                        loop_evidence.target
                    ),
                },
            },
        );
    }
}

fn detect_frame_state(section: &DisassembledSection) -> FrameState {
    let mut state = FrameState::default();

    for instruction in section.instructions.iter().take(FRAME_SETUP_SCAN_LIMIT) {
        let mnemonic = instruction.mnemonic.to_ascii_lowercase();
        let operands = instruction
            .detail
            .as_ref()
            .map(|detail| detail.operands.as_slice());

        if mnemonic == "mov"
            && let Some(
                [
                    OperandDetail::Register {
                        name: Some(dst), ..
                    },
                    OperandDetail::Register {
                        name: Some(src), ..
                    },
                    ..,
                ],
            ) = operands
        {
            match (dst.as_str(), src.as_str()) {
                ("rbp", "rsp") => {
                    state.base = Some(FrameBase::Rbp);
                    state.frame_pointer_established = true;
                }
                ("ebp", "esp") => {
                    state.base = Some(FrameBase::Ebp);
                    state.frame_pointer_established = true;
                }
                _ => {}
            }
        }

        if mnemonic == "sub"
            && let Some(
                [
                    OperandDetail::Register {
                        name: Some(dst), ..
                    },
                    OperandDetail::Immediate { value, .. },
                    ..,
                ],
            ) = operands
        {
            match dst.as_str() {
                "rsp" => {
                    state.base.get_or_insert(FrameBase::Rsp);
                    if *value > 0 {
                        state.size = Some(*value);
                    }
                }
                "esp" => {
                    state.base.get_or_insert(FrameBase::Esp);
                    if *value > 0 {
                        state.size = Some(*value);
                    }
                }
                _ => {}
            }
        }
    }

    state
}

fn detect_loops(section: &DisassembledSection) -> Vec<LoopEvidence> {
    let mut loops = Vec::new();

    for (index, instruction) in section.instructions.iter().enumerate() {
        let Some(target) = jump_target(instruction) else {
            continue;
        };
        if target >= instruction.address {
            continue;
        }

        let Some(start) = section
            .instructions
            .iter()
            .position(|candidate| candidate.address >= target)
        else {
            continue;
        };

        let compare = section.instructions[start..=index]
            .iter()
            .rev()
            .find_map(compare_register_bound);

        loops.push(LoopEvidence {
            start,
            end: index,
            target,
            counter_register: compare.as_ref().map(|(register, _)| register.clone()),
            bound: compare.map(|(_, bound)| bound),
        });
    }

    loops
}

fn compare_register_bound(instruction: &Instruction) -> Option<(String, i64)> {
    if !instruction.mnemonic.eq_ignore_ascii_case("cmp") {
        return None;
    }

    let operands = instruction.detail.as_ref()?.operands.as_slice();
    match operands {
        [
            OperandDetail::Register {
                name: Some(register),
                ..
            },
            OperandDetail::Immediate { value, .. },
            ..,
        ]
        | [
            OperandDetail::Immediate { value, .. },
            OperandDetail::Register {
                name: Some(register),
                ..
            },
            ..,
        ] => Some((register.clone(), *value)),
        _ => None,
    }
}

fn jump_target(instruction: &Instruction) -> Option<u64> {
    let detail = instruction.detail.as_ref()?;
    if !detail.groups.iter().any(|group| group == "jump") {
        return None;
    }

    detail.operands.iter().find_map(|operand| match operand {
        OperandDetail::Immediate { value, .. } if *value >= 0 => Some(*value as u64),
        _ => None,
    })
}

fn memory_writes(instruction: &Instruction) -> Vec<MemoryOperandRef<'_>> {
    instruction
        .detail
        .as_ref()
        .map(|detail| {
            detail
                .operands
                .iter()
                .filter_map(|operand| match operand {
                    OperandDetail::Memory {
                        base,
                        index,
                        disp,
                        access,
                        size,
                        ..
                    } if matches!(
                        access,
                        Some(OperandAccess::WriteOnly | OperandAccess::ReadWrite)
                    ) =>
                    {
                        Some(MemoryOperandRef {
                            base: base.as_deref(),
                            index: index.as_deref(),
                            disp: *disp,
                            access: *access,
                            size: *size,
                        })
                    }
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

fn out_of_bounds_stack_write_reason(
    frame: FrameState,
    memory: &MemoryOperandRef<'_>,
) -> Option<String> {
    let frame_size = frame.size?;
    let base = memory.base?;

    match base {
        "rbp" | "ebp"
            if frame.frame_pointer_established && memory.disp < 0 && memory.index.is_none() =>
        {
            let start = -memory.disp;
            let end = start + i64::from(memory.size);
            if end > frame_size {
                Some(format!(
                    "Stack-relative write starts {:#x} bytes below the frame pointer and spans {} bytes, which exceeds the inferred frame size of {:#x} bytes.",
                    start, memory.size, frame_size
                ))
            } else {
                None
            }
        }
        "rsp" | "esp" if memory.disp >= 0 && memory.index.is_none() => {
            let end = memory.disp + i64::from(memory.size);
            if end > frame_size {
                Some(format!(
                    "Stack-pointer-relative write reaches offset {:#x} with width {}, beyond the inferred stack frame size of {:#x} bytes.",
                    end, memory.size, frame_size
                ))
            } else {
                None
            }
        }
        _ => None,
    }
}

fn stack_pointer_anomaly_reason(
    frame: FrameState,
    memory: &MemoryOperandRef<'_>,
) -> Option<String> {
    let base = memory.base?;
    match (frame.base, base, memory.index) {
        (Some(FrameBase::Rsp | FrameBase::Esp), "rsp" | "esp", Some(index)) => Some(format!(
            "Indexed write uses the live stack pointer as the addressing base with index register {index}, which makes frame-relative bounds harder to recover conservatively."
        )),
        _ => None,
    }
}

fn unsafe_frame_write_reason(frame: FrameState, memory: &MemoryOperandRef<'_>) -> Option<String> {
    if !frame.frame_pointer_established {
        return None;
    }

    if matches!(memory.base, Some("rbp" | "ebp")) && memory.disp >= 0 {
        return Some(format!(
            "Instruction writes at displacement {:+#x} from an established frame pointer into non-local stack space above the current frame.",
            memory.disp
        ));
    }

    None
}

fn is_indirect_non_stack_write(memory: &MemoryOperandRef<'_>) -> bool {
    !is_stack_base(memory.base)
        && !matches!(memory.base, Some("rip" | "eip"))
        && memory.base.is_some()
        && matches!(
            memory.access,
            Some(OperandAccess::WriteOnly | OperandAccess::ReadWrite)
        )
}

fn estimate_stack_capacity(frame: FrameState, memory: &MemoryOperandRef<'_>) -> Option<i64> {
    let base = memory.base?;
    match base {
        "rbp" | "ebp" if frame.frame_pointer_established && memory.disp < 0 => Some(-memory.disp),
        "rsp" | "esp" if memory.disp >= 0 => frame.size.map(|size| size - memory.disp),
        _ => None,
    }
    .filter(|capacity| *capacity > 0)
}

fn frame_supports_stack_capacity(frame: FrameState, memory: &MemoryOperandRef<'_>) -> bool {
    match memory.base {
        Some("rbp" | "ebp") => frame.frame_pointer_established,
        Some("rsp" | "esp") => frame.size.is_some(),
        _ => false,
    }
}

fn loop_bound_matches_write_progress(
    loop_evidence: &LoopEvidence,
    memory: &MemoryOperandRef<'_>,
) -> bool {
    loop_evidence.counter_register.as_deref() == memory.index
        || loop_evidence.counter_register.as_deref() == memory.base
}

fn is_stack_base(base: Option<&str>) -> bool {
    matches!(base, Some("rbp" | "rsp" | "ebp" | "esp"))
}

fn push_finding(findings: &mut Vec<Finding>, finding: Finding) {
    if findings
        .iter()
        .any(|existing| existing.kind == finding.kind && existing.address == finding.address)
    {
        return;
    }
    findings.push(finding);
}

impl FindingKind {
    fn label(self) -> &'static str {
        match self {
            Self::PotentialStackBufferWriteRisk => "potential-stack-buffer-write-risk",
            Self::PossibleOutOfBoundsLocalWrite => "possible-out-of-bounds-local-write",
            Self::SuspiciousCopyLoop => "suspicious-copy-loop",
            Self::UnsafeStackFrameWrite => "unsafe-stack-frame-write",
            Self::StackPointerFramePointerAnomaly => "stack-pointer-frame-pointer-anomaly",
            Self::IndirectWriteRisk => "indirect-write-risk",
        }
    }
}

impl Severity {
    fn label(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
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

fn render_box(title_plain: &str, title_styled: &str, lines: &[StyledLine]) -> String {
    let inner_width = lines
        .iter()
        .map(|line| UnicodeWidthStr::width(line.plain.as_str()))
        .max()
        .unwrap_or_default()
        .max(UnicodeWidthStr::width(title_plain) + 1);

    let mut output = String::new();
    let fill = inner_width.saturating_sub(UnicodeWidthStr::width(title_plain));
    let _ = writeln!(output, "╭─ {}{}╮", title_styled, "─".repeat(fill));
    for line in lines {
        let padding = inner_width.saturating_sub(UnicodeWidthStr::width(line.plain.as_str()));
        let _ = writeln!(output, "│ {}{} │", line.styled, " ".repeat(padding));
    }
    let _ = write!(output, "╰{}╯", "─".repeat(inner_width + 2));
    output
}

fn escape_for_terminal(raw: &str) -> String {
    raw.chars()
        .flat_map(|character| character.escape_default())
        .collect()
}

fn format_address(address: u64) -> String {
    format!("{address:#018x}")
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

fn style_meta_key(text: &str, color_enabled: bool) -> String {
    style_text(text, color_enabled, &["1", "90"])
}

fn style_meta_value(text: &str, color_enabled: bool) -> String {
    style_text(text, color_enabled, &["97"])
}

fn style_note(text: &str, color_enabled: bool) -> String {
    style_text(text, color_enabled, &["3", "90"])
}

fn style_address(text: &str, color_enabled: bool) -> String {
    style_text(text, color_enabled, &["1", "96"])
}

fn style_kind(text: &str, color_enabled: bool) -> String {
    style_text(text, color_enabled, &["1", "95"])
}

fn style_severity(text: &str, severity: Severity, color_enabled: bool) -> String {
    let codes = match severity {
        Severity::Low => &["1", "94"][..],
        Severity::Medium => &["1", "93"][..],
        Severity::High => &["1", "91"][..],
    };
    style_text(text, color_enabled, codes)
}

#[cfg(test)]
mod tests {
    use super::{
        AnalysisReport, FindingKind, Severity, analyze, escape_for_terminal, render_box,
        style_box_title,
    };
    use crate::disasm::{
        Architecture, DisassembledSection, DisassemblyReport, Instruction, InstructionDetail,
        OperandAccess, OperandDetail, RenderOptions,
    };
    use std::collections::BTreeMap;

    fn mem_write(base: &str, index: Option<&str>, disp: i64, size: u8) -> OperandDetail {
        OperandDetail::Memory {
            segment: None,
            base: Some(base.into()),
            index: index.map(str::to_owned),
            scale: 1,
            disp,
            access: Some(OperandAccess::WriteOnly),
            size,
        }
    }

    fn reg(name: &str) -> OperandDetail {
        OperandDetail::Register {
            name: Some(name.into()),
            access: Some(OperandAccess::ReadOnly),
            size: 8,
        }
    }

    fn reg_write(name: &str) -> OperandDetail {
        OperandDetail::Register {
            name: Some(name.into()),
            access: Some(OperandAccess::WriteOnly),
            size: 8,
        }
    }

    fn imm(value: i64) -> OperandDetail {
        OperandDetail::Immediate { value, size: 8 }
    }

    fn instruction(
        address: u64,
        mnemonic: &str,
        operands: &str,
        detail: InstructionDetail,
    ) -> Instruction {
        Instruction {
            address,
            bytes: vec![],
            mnemonic: mnemonic.into(),
            operands: operands.into(),
            detail: Some(detail),
        }
    }

    fn report_with_instructions(instructions: Vec<Instruction>) -> DisassemblyReport {
        DisassemblyReport {
            target: "<test>".into(),
            architecture: Architecture::X86_64,
            metadata: vec![("architecture".into(), "x86_64".into())],
            sections: vec![DisassembledSection {
                name: ".text::sample".into(),
                address: 0x1000,
                size: instructions.len() as u64,
                labels: BTreeMap::new(),
                instructions,
            }],
        }
    }

    #[test]
    fn reports_no_findings_when_evidence_is_missing() {
        let report = report_with_instructions(vec![instruction(
            0x1000,
            "cmp",
            "byte ptr [rdi], 0x6f",
            InstructionDetail {
                groups: vec![],
                operands: vec![
                    OperandDetail::Memory {
                        segment: None,
                        base: Some("rdi".into()),
                        index: None,
                        scale: 1,
                        disp: 0,
                        access: Some(OperandAccess::ReadOnly),
                        size: 1,
                    },
                    OperandDetail::Immediate {
                        value: 0x6f,
                        size: 1,
                    },
                ],
            },
        )]);

        let analysis = analyze(&report);
        assert!(analysis.findings.is_empty());
        assert!(
            analysis
                .render(&RenderOptions::plain(false))
                .contains("No supported memory-safety findings")
        );
    }

    #[test]
    fn detects_loop_driven_stack_write_risk() {
        let report = report_with_instructions(vec![
            instruction(
                0x1000,
                "mov",
                "rbp, rsp",
                InstructionDetail {
                    groups: vec![],
                    operands: vec![reg_write("rbp"), reg("rsp")],
                },
            ),
            instruction(
                0x1003,
                "sub",
                "rsp, 0x20",
                InstructionDetail {
                    groups: vec![],
                    operands: vec![reg_write("rsp"), imm(0x20)],
                },
            ),
            instruction(
                0x1007,
                "mov",
                "byte ptr [rbp + rax - 0x10], 0x41",
                InstructionDetail {
                    groups: vec![],
                    operands: vec![mem_write("rbp", Some("rax"), -0x10, 1), imm(0x41)],
                },
            ),
            instruction(
                0x100c,
                "cmp",
                "rax, 0x40",
                InstructionDetail {
                    groups: vec![],
                    operands: vec![reg("rax"), imm(0x40)],
                },
            ),
            instruction(
                0x1010,
                "jne",
                "0x1007",
                InstructionDetail {
                    groups: vec!["jump".into(), "branch_relative".into()],
                    operands: vec![imm(0x1007)],
                },
            ),
        ]);

        let analysis = analyze(&report);
        assert!(
            analysis
                .findings
                .iter()
                .any(|finding| finding.kind == FindingKind::PotentialStackBufferWriteRisk)
        );
        assert!(
            analysis
                .findings
                .iter()
                .any(|finding| finding.kind == FindingKind::PossibleOutOfBoundsLocalWrite)
        );
        assert!(
            analysis
                .findings
                .iter()
                .any(|finding| finding.kind == FindingKind::SuspiciousCopyLoop)
        );
    }

    #[test]
    fn detects_unsafe_frame_write() {
        let report = report_with_instructions(vec![
            instruction(
                0x1000,
                "mov",
                "rbp, rsp",
                InstructionDetail {
                    groups: vec![],
                    operands: vec![reg_write("rbp"), reg("rsp")],
                },
            ),
            instruction(
                0x1004,
                "mov",
                "qword ptr [rbp + 8], rax",
                InstructionDetail {
                    groups: vec![],
                    operands: vec![mem_write("rbp", None, 8, 8), reg("rax")],
                },
            ),
        ]);

        let analysis = analyze(&report);
        let finding = analysis
            .findings
            .iter()
            .find(|finding| finding.kind == FindingKind::UnsafeStackFrameWrite)
            .expect("expected unsafe frame write finding");
        assert_eq!(finding.severity, Severity::Medium);
    }

    #[test]
    fn does_not_report_unsafe_frame_write_without_frame_pointer_evidence() {
        let report = report_with_instructions(vec![instruction(
            0x1000,
            "mov",
            "qword ptr [rbp + 8], rax",
            InstructionDetail {
                groups: vec![],
                operands: vec![mem_write("rbp", None, 8, 8), reg("rax")],
            },
        )]);

        let analysis = analyze(&report);
        assert!(
            !analysis
                .findings
                .iter()
                .any(|finding| finding.kind == FindingKind::UnsafeStackFrameWrite)
        );
    }

    #[test]
    fn does_not_apply_loop_bound_from_unrelated_register() {
        let report = report_with_instructions(vec![
            instruction(
                0x1000,
                "mov",
                "rbp, rsp",
                InstructionDetail {
                    groups: vec![],
                    operands: vec![reg_write("rbp"), reg("rsp")],
                },
            ),
            instruction(
                0x1003,
                "sub",
                "rsp, 0x20",
                InstructionDetail {
                    groups: vec![],
                    operands: vec![reg_write("rsp"), imm(0x20)],
                },
            ),
            instruction(
                0x1007,
                "mov",
                "byte ptr [rbp + rcx - 0x10], 0x41",
                InstructionDetail {
                    groups: vec![],
                    operands: vec![mem_write("rbp", Some("rcx"), -0x10, 1), imm(0x41)],
                },
            ),
            instruction(
                0x100c,
                "cmp",
                "rax, 0x40",
                InstructionDetail {
                    groups: vec![],
                    operands: vec![reg("rax"), imm(0x40)],
                },
            ),
            instruction(
                0x1010,
                "jne",
                "0x1007",
                InstructionDetail {
                    groups: vec!["jump".into(), "branch_relative".into()],
                    operands: vec![imm(0x1007)],
                },
            ),
        ]);

        let analysis = analyze(&report);
        assert!(!analysis.findings.iter().any(|finding| {
            matches!(
                finding.kind,
                FindingKind::PotentialStackBufferWriteRisk
                    | FindingKind::PossibleOutOfBoundsLocalWrite
            ) && finding.rationale.contains("immediate bound 64")
        }));
        assert!(
            analysis
                .findings
                .iter()
                .any(|finding| finding.kind == FindingKind::SuspiciousCopyLoop)
        );
    }

    #[test]
    fn reports_indirect_write_risk_for_non_stack_pointer_writes() {
        let report = report_with_instructions(vec![instruction(
            0x1000,
            "mov",
            "dword ptr [rdi + rcx * 4], eax",
            InstructionDetail {
                groups: vec![],
                operands: vec![mem_write("rdi", Some("rcx"), 0, 4), reg("eax")],
            },
        )]);

        let analysis = analyze(&report);
        assert!(
            analysis
                .findings
                .iter()
                .any(|finding| finding.kind == FindingKind::IndirectWriteRisk)
        );
    }

    #[test]
    fn reports_stack_pointer_anomaly_for_indexed_rsp_writes() {
        let report = report_with_instructions(vec![
            instruction(
                0x1000,
                "sub",
                "rsp, 0x20",
                InstructionDetail {
                    groups: vec![],
                    operands: vec![reg_write("rsp"), imm(0x20)],
                },
            ),
            instruction(
                0x1004,
                "mov",
                "byte ptr [rsp + rcx], 0x41",
                InstructionDetail {
                    groups: vec![],
                    operands: vec![mem_write("rsp", Some("rcx"), 0, 1), imm(0x41)],
                },
            ),
        ]);

        let analysis = analyze(&report);
        assert!(
            analysis
                .findings
                .iter()
                .any(|finding| finding.kind == FindingKind::StackPointerFramePointerAnomaly)
        );
    }

    #[test]
    fn pretty_analysis_render_uses_box_layout() {
        let analysis = AnalysisReport {
            architecture: Architecture::X86_64,
            findings: vec![],
            notes: vec!["No supported memory-safety findings were identified.".into()],
        };

        let rendered = analysis.render(&RenderOptions::pretty(false));
        assert!(rendered.contains("╭─ ANALYSIS"));
        assert!(rendered.contains("architecture x86_64"));
    }

    #[test]
    fn escapes_terminal_content() {
        assert_eq!(
            escape_for_terminal("bad\n\x1b[31mnote"),
            "bad\\n\\u{1b}[31mnote"
        );
    }

    #[test]
    fn analysis_box_renderer_keeps_title_visible() {
        let rendered = render_box(
            "analysis",
            &style_box_title("ANALYSIS", false),
            &[super::StyledLine::plain("note hello".into())],
        );
        assert!(rendered.contains("ANALYSIS"));
    }
}
