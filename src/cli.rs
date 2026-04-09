use std::path::PathBuf;

use anyhow::{Result, anyhow, bail};
use clap::{Parser, ValueEnum};

use crate::types::{Architecture, DisasmInput, DisasmRequest, RenderOptions, Syntax};

#[derive(Debug, Parser)]
#[command(
    name = "assembler",
    version,
    about = "Disassemble executable code from binaries or raw bytes"
)]
pub struct Cli {
    /// Path to the binary/object file to disassemble.
    #[arg(value_name = "FILE", required_unless_present = "raw_hex")]
    pub input: Option<PathBuf>,

    /// Raw hex bytes to disassemble, e.g. "55 48 89 e5 5d c3".
    #[arg(long, conflicts_with = "input", value_name = "HEX")]
    pub raw_hex: Option<String>,

    /// Force architecture for raw disassembly or override auto-detection.
    #[arg(long, value_enum)]
    pub arch: Option<CliArchitecture>,

    /// Base address used for raw disassembly output.
    #[arg(long, value_parser = parse_u64, default_value = "0x0")]
    pub base_address: u64,

    /// Disassemble every non-empty section instead of only executable ones.
    #[arg(long)]
    pub all_sections: bool,

    /// Restrict disassembly to one or more named sections.
    #[arg(short, long = "section", value_name = "NAME")]
    pub sections: Vec<String>,

    /// Restrict file disassembly to one or more symbol names.
    #[arg(long = "symbol", value_name = "NAME")]
    pub symbols: Vec<String>,

    /// Syntax used for x86/x86_64 output.
    #[arg(long, value_enum, default_value_t = CliSyntax::Intel)]
    pub syntax: CliSyntax,

    /// Control ANSI colors in the rendered output.
    #[arg(long, value_enum, default_value_t = CliColor::Auto)]
    pub color: CliColor,

    /// Control the render style. Auto uses pretty boxes on terminals and plain output elsewhere.
    #[arg(long, value_enum, default_value_t = CliRender::Auto)]
    pub render: CliRender,

    /// Select text or JSON output.
    #[arg(long, value_enum, default_value_t = CliOutput::Text)]
    pub output: CliOutput,

    /// Run conservative semantic risk analysis on decoded disassembly.
    #[arg(long)]
    pub analyze: bool,

    /// Exit with code 1 when --analyze produces one or more findings.
    #[arg(long, requires = "analyze")]
    pub analyze_exit_code: bool,
}

impl Cli {
    pub fn render_options(
        &self,
        stdout_is_terminal: bool,
        no_color: bool,
        term_is_dumb: bool,
    ) -> RenderOptions {
        let color_enabled = self
            .color
            .should_colorize(stdout_is_terminal, no_color, term_is_dumb);
        let pretty = self.render.should_pretty(stdout_is_terminal);
        if !pretty {
            return RenderOptions::plain(color_enabled);
        }

        RenderOptions::pretty(color_enabled)
    }

    pub fn into_request(self) -> Result<DisasmRequest> {
        let input = match self.raw_hex {
            Some(bytes) => DisasmInput::RawHex(bytes),
            None => DisasmInput::File(
                self.input
                    .ok_or_else(|| anyhow!("either FILE or --raw-hex must be provided"))?,
            ),
        };

        Ok(DisasmRequest {
            input,
            architecture: self.arch.map(Into::into),
            syntax: self.syntax.into(),
            base_address: self.base_address,
            all_sections: self.all_sections,
            sections: self.sections,
            symbols: self.symbols,
            analyze: self.analyze,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum CliArchitecture {
    X86,
    X86_64,
    Arm,
    Thumb,
    Aarch64,
}

impl From<CliArchitecture> for Architecture {
    fn from(value: CliArchitecture) -> Self {
        match value {
            CliArchitecture::X86 => Architecture::X86,
            CliArchitecture::X86_64 => Architecture::X86_64,
            CliArchitecture::Arm => Architecture::Arm,
            CliArchitecture::Thumb => Architecture::Thumb,
            CliArchitecture::Aarch64 => Architecture::Aarch64,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum CliSyntax {
    Intel,
    Att,
}

impl From<CliSyntax> for Syntax {
    fn from(value: CliSyntax) -> Self {
        match value {
            CliSyntax::Intel => Syntax::Intel,
            CliSyntax::Att => Syntax::Att,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum CliColor {
    Auto,
    Always,
    Never,
}

impl CliColor {
    pub fn should_colorize(
        self,
        stdout_is_terminal: bool,
        no_color: bool,
        term_is_dumb: bool,
    ) -> bool {
        match self {
            Self::Auto => stdout_is_terminal && !no_color && !term_is_dumb,
            Self::Always => true,
            Self::Never => false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum CliRender {
    Auto,
    Pretty,
    Plain,
}

impl CliRender {
    pub fn should_pretty(self, stdout_is_terminal: bool) -> bool {
        match self {
            Self::Auto => stdout_is_terminal,
            Self::Pretty => true,
            Self::Plain => false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum CliOutput {
    Text,
    Json,
}

fn parse_u64(raw: &str) -> Result<u64> {
    let value = raw.trim();
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        return u64::from_str_radix(hex, 16).map_err(Into::into);
    }

    if value.is_empty() {
        bail!("numeric value cannot be empty");
    }

    value.parse::<u64>().map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::{CliColor, CliRender, parse_u64};

    #[test]
    fn parses_hex_numbers() {
        assert_eq!(parse_u64("0x401000").unwrap(), 0x401000);
    }

    #[test]
    fn parses_decimal_numbers() {
        assert_eq!(parse_u64("4096").unwrap(), 4096);
    }

    #[test]
    fn rejects_empty_numbers() {
        assert!(parse_u64("  ").is_err());
    }

    #[test]
    fn auto_color_respects_terminal_capabilities() {
        assert!(CliColor::Auto.should_colorize(true, false, false));
        assert!(!CliColor::Auto.should_colorize(false, false, false));
        assert!(!CliColor::Auto.should_colorize(true, true, false));
        assert!(!CliColor::Auto.should_colorize(true, false, true));
    }

    #[test]
    fn explicit_color_overrides_environment_hints() {
        assert!(CliColor::Always.should_colorize(false, true, true));
        assert!(!CliColor::Never.should_colorize(true, false, false));
    }

    #[test]
    fn auto_color_treats_no_color_presence_as_disable() {
        assert!(!CliColor::Auto.should_colorize(true, true, false));
    }

    #[test]
    fn auto_render_pretty_only_on_terminals() {
        assert!(CliRender::Auto.should_pretty(true));
        assert!(!CliRender::Auto.should_pretty(false));
        assert!(CliRender::Pretty.should_pretty(false));
        assert!(!CliRender::Plain.should_pretty(true));
    }
}
