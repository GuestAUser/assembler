use std::collections::BTreeMap;
use std::path::PathBuf;

use object::Architecture as ObjectArchitecture;
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct DisasmRequest {
    pub input: DisasmInput,
    pub architecture: Option<Architecture>,
    pub syntax: Syntax,
    pub base_address: u64,
    pub all_sections: bool,
    pub sections: Vec<String>,
    pub symbols: Vec<String>,
    pub analyze: bool,
}

#[derive(Clone, Debug, Serialize)]
pub enum DisasmInput {
    File(PathBuf),
    RawHex(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum Architecture {
    X86,
    X86_64,
    Arm,
    Thumb,
    Aarch64,
}

impl Architecture {
    pub(crate) fn from_object(architecture: ObjectArchitecture) -> Option<Self> {
        match architecture {
            ObjectArchitecture::I386 => Some(Self::X86),
            ObjectArchitecture::X86_64 => Some(Self::X86_64),
            ObjectArchitecture::Arm => Some(Self::Arm),
            ObjectArchitecture::Aarch64 | ObjectArchitecture::Aarch64_Ilp32 => Some(Self::Aarch64),
            _ => None,
        }
    }

    pub(crate) fn display_name(self) -> &'static str {
        match self {
            Self::X86 => "x86",
            Self::X86_64 => "x86_64",
            Self::Arm => "arm",
            Self::Thumb => "thumb",
            Self::Aarch64 => "aarch64",
        }
    }

    pub(crate) fn supports_syntax_metadata(self) -> bool {
        matches!(self, Self::X86 | Self::X86_64)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum Syntax {
    Intel,
    Att,
}

impl Syntax {
    pub(crate) fn display_name(self) -> &'static str {
        match self {
            Self::Intel => "intel",
            Self::Att => "att",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct RenderOptions {
    pub(crate) pretty: bool,
    pub(crate) color_enabled: bool,
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

    pub(crate) fn is_pretty(&self) -> bool {
        self.pretty
    }

    pub(crate) fn color_enabled(&self) -> bool {
        self.color_enabled
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DisassemblyReport {
    pub(crate) target: String,
    pub(crate) architecture: Architecture,
    pub(crate) metadata: Vec<(String, String)>,
    pub(crate) sections: Vec<DisassembledSection>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct DisassembledSection {
    pub(crate) name: String,
    pub(crate) address: u64,
    pub(crate) size: u64,
    pub(crate) labels: BTreeMap<u64, Vec<String>>,
    pub(crate) instructions: Vec<Instruction>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub(crate) enum OperandAccess {
    ReadOnly,
    WriteOnly,
    ReadWrite,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) enum OperandDetail {
    Register {
        name: Option<String>,
        access: Option<OperandAccess>,
        size: u8,
    },
    Immediate {
        value: i64,
        size: u8,
    },
    Memory {
        segment: Option<String>,
        base: Option<String>,
        index: Option<String>,
        scale: i32,
        disp: i64,
        access: Option<OperandAccess>,
        size: u8,
    },
    Invalid,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub(crate) struct InstructionDetail {
    pub(crate) groups: Vec<String>,
    pub(crate) operands: Vec<OperandDetail>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Instruction {
    pub(crate) address: u64,
    pub(crate) bytes: Vec<u8>,
    pub(crate) mnemonic: String,
    pub(crate) operands: String,
    pub(crate) detail: Option<InstructionDetail>,
}
