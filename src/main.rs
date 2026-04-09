mod cli;
mod disasm;

use std::env;
use std::io::{self, IsTerminal};

use anyhow::Result;
use clap::Parser;

fn main() -> Result<()> {
    let cli = cli::Cli::parse();
    let stdout_is_terminal = io::stdout().is_terminal();
    let no_color = env::var_os("NO_COLOR").is_some();
    let term_is_dumb = env::var_os("TERM")
        .is_some_and(|value| value.to_string_lossy().eq_ignore_ascii_case("dumb"));
    let render_options = cli.render_options(stdout_is_terminal, no_color, term_is_dumb);
    let report = disasm::disassemble(cli.into_request()?)?;
    print!("{}", report.render(&render_options));
    Ok(())
}
