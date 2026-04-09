mod analysis;
mod cli;
mod disasm;
mod render;
mod types;

use std::env;
use std::io::{self, IsTerminal, Write as _};
use std::process;

use anyhow::Result;
use clap::Parser;
use serde::Serialize;

use crate::cli::CliOutput;

#[derive(Serialize)]
struct OutputDocument<'a> {
    disassembly: &'a types::DisassemblyReport,
    #[serde(skip_serializing_if = "Option::is_none")]
    analysis: Option<&'a analysis::AnalysisReport>,
}

fn main() -> Result<()> {
    let cli = cli::Cli::parse();
    let stdout_is_terminal = io::stdout().is_terminal();
    let no_color = env::var_os("NO_COLOR").is_some();
    let term_is_dumb = env::var_os("TERM")
        .is_some_and(|value| value.to_string_lossy().eq_ignore_ascii_case("dumb"));
    let render_options = cli.render_options(stdout_is_terminal, no_color, term_is_dumb);
    let analyze = cli.analyze;
    let output_format = cli.output;
    let analyze_exit_code = cli.analyze_exit_code;
    let report = disasm::disassemble(cli.into_request()?)?;
    let analysis = analyze.then(|| analysis::analyze(&report));

    match output_format {
        CliOutput::Text => {
            print!("{}", report.render(&render_options));
            if let Some(analysis) = &analysis {
                print!("{}", analysis.render(&render_options));
            }
        }
        CliOutput::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&OutputDocument {
                    disassembly: &report,
                    analysis: analysis.as_ref(),
                })?
            );
        }
    }

    if analyze_exit_code
        && analysis
            .as_ref()
            .is_some_and(analysis::AnalysisReport::has_findings)
    {
        let _ = io::stdout().flush();
        process::exit(1);
    }

    Ok(())
}
