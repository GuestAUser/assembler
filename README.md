# assembler

<p align="center">
  <strong>A Rust disassembler for raw machine code, object-backed binaries, symbol-scoped inspection, and conservative semantic analysis.</strong>
</p>

<p align="center">
  Built for low-friction terminal workflows, deterministic verification, and evidence-backed output rather than decompiler theater.
</p>

## Preview

### Pretty output

<p align="center">
  <img src="cape1.png" alt="assembler pretty output" width="100%" />
</p>

### Plain output

<p align="center">
  <img src="cape2.png" alt="assembler plain output" width="100%" />
</p>

### Analysis output

<p align="center">
  <img src="cape3.png" alt="assembler analysis output" width="100%" />
</p>

## What this tool is

`assembler` is a command-line disassembly frontend implemented in Rust.

It:

- decodes raw opcode streams and object-backed executable code through [Capstone](https://github.com/capstone-engine/capstone)
- resolves section and symbol context through [`object`](https://crates.io/crates/object)
- renders normalized assembly in either terminal-friendly pretty mode or grep-friendly plain mode
- emits structured JSON for automation and CI usage
- optionally runs a conservative semantic analyzer for x86 and x86_64 disassembly

It is intentionally **not** a decompiler, source reconstructor, symbolic executor, or exploitability oracle.

## Design principles

- **Deterministic decoding surface**: explicit architecture selection when metadata is insufficient; no silent guessing for ARM/Thumb raw modes
- **Symbol-first workflow**: real binary and object-file inspection with symbol and section filtering instead of only byte-stream demos
- **Terminal-safe output**: hostile strings are escaped before rendering, and non-interactive output defaults to a stable plain-text layout
- **Conservative analysis**: findings are derived from operand semantics, memory addressing, and control-flow evidence—not from mnemonic names or imported APIs
- **Regression-proof development**: fixture binaries use exact `global_asm!` symbols so verification is not hostage to compiler codegen drift

## Table of contents

- [Build and installation](#build-and-installation)
- [Command model](#command-model)
- [Common workflows](#common-workflows)
- [Output formats](#output-formats)
- [Semantic analysis](#semantic-analysis)
- [Deterministic fixture corpus](#deterministic-fixture-corpus)
- [Reverse-engineering example](#reverse-engineering-example)
- [Architecture support and limits](#architecture-support-and-limits)
- [Safety and robustness](#safety-and-robustness)
- [Verification](#verification)
- [Project layout](#project-layout)
- [Implementation stack](#implementation-stack)

## Build and installation

### Build from source

```bash
cargo build --release
```

### Install locally

```bash
cargo install --path .
```

### Requirements

- Rust toolchain (edition 2024)
- a C compiler only if you want to build the optional demo target in `examples/password-login/`

## Command model

```text
assembler [FILE] [OPTIONS]
assembler --raw-hex <HEX> --arch <ARCH> [OPTIONS]
```

The CLI operates in two disjoint input modes:

| Mode | Trigger | Decode source |
|---|---|---|
| **File mode** | positional `FILE` | section and symbol data from object metadata |
| **Raw-byte mode** | `--raw-hex <HEX>` | direct decode of user-provided bytes |

Raw-byte mode requires `--arch` because there is no container metadata to infer decode mode safely.

### Core options

| Flag | Meaning |
|---|---|
| `--arch <x86\|x86-64\|arm\|thumb\|aarch64>` | force architecture or override file-mode auto detection |
| `--symbol <NAME>` | restrict file disassembly to one or more symbol names |
| `--section <NAME>` | restrict file disassembly to one or more section names |
| `--all-sections` | disassemble every non-empty section instead of executable sections only |
| `--syntax <intel\|att>` | x86/x86_64 syntax selection |
| `--render <auto\|pretty\|plain>` | layout selection |
| `--color <auto\|always\|never>` | ANSI color control |
| `--output <text\|json>` | human-readable output or structured JSON |
| `--analyze` | append semantic analysis output |
| `--analyze-exit-code` | return exit code `1` when analysis findings exist |
| `--base-address <ADDR>` | override base address for raw-byte decoding |

### Important mode constraints

- `--symbol`, `--section`, and `--all-sections` are **file-mode only**
- `--base-address` is only meaningful for raw-byte decoding
- `--syntax att` only affects x86 and x86_64 output
- ARM object files require explicit `--arch arm` or `--arch thumb`

## Common workflows

### Show CLI help

```bash
cargo run -- --help
```

### Decode a minimal x86_64 function from raw bytes

```bash
cargo run -- --raw-hex "55 48 89 e5 5d c3" --arch x86-64
```

### Disassemble a single symbol from a binary

```bash
cargo run -- ./target/debug/assembler --symbol main
```

### Restrict file output to selected sections

```bash
cargo run -- ./target/debug/assembler --section .text --section .init
```

### Force pretty output without ANSI color

```bash
cargo run -- --raw-hex "55 48 89 e5 5d c3" --arch x86-64 --render pretty --color never
```

### Force plain output with color

```bash
cargo run -- --raw-hex "55 48 89 e5 5d c3" --arch x86-64 --render plain --color always
```

### Run analysis and get machine-readable JSON

```bash
cargo run -- ./target/debug/assembler --symbol main --analyze --output json
```

### Gate CI on findings

```bash
cargo run -- ./target/debug/assembler --symbol main --analyze --analyze-exit-code
```

## Output formats

### Text output

The text renderer has two layouts:

| Mode | Behavior |
|---|---|
| `pretty` | structured box layout optimized for interactive reading |
| `plain` | flat, grep-friendly text optimized for logs, pipes, and captured output |
| `auto` | pretty on TTYs, plain on captured or piped stdout |

Color behavior:

| Mode | Behavior |
|---|---|
| `auto` | enabled on terminals, disabled when `NO_COLOR` is present or `TERM=dumb` |
| `always` | ANSI sequences always emitted |
| `never` | ANSI disabled entirely |

### JSON output

`--output json` emits a stable structured document:

```json
{
  "disassembly": {
    "target": "...",
    "architecture": "X86_64",
    "metadata": [["format", "Elf"], ...],
    "sections": [...]
  },
  "analysis": {
    "architecture": "X86_64",
    "findings": [...],
    "notes": [...]
  }
}
```

`analysis` is omitted when `--analyze` is not requested.

## Semantic analysis

`--analyze` runs a post-decoding pass that consumes Capstone detail-mode output and reasons over:

- typed operands
- access direction
- stack-relative memory addressing
- frame setup patterns
- basic-block control flow and loop back-edges

It does **not** inspect rendered text for keywords and does **not** claim exploitability from disassembly alone.

### Internal model

```text
CLI
  → DisasmRequest
  → Capstone decode (detail mode)
  → DisassemblyReport
  → analyze()
  → AnalysisReport
  → text or JSON render
```

### Current finding classes

| Class | Meaning |
|---|---|
| `potential-stack-buffer-write-risk` | repeated indexed writes into stack-local memory with evidence that progression exceeds inferred capacity |
| `possible-out-of-bounds-local-write` | single or loop-driven local write whose offset plus width exceeds inferred frame bounds |
| `suspicious-copy-loop` | backward-branch write loop with weak or unrecoverable destination bound evidence |
| `unsafe-stack-frame-write` | write above the local frame through an established frame pointer |
| `stack-pointer-frame-pointer-anomaly` | indexed write using live stack pointer as base |
| `indirect-write-risk` | memory write through a non-stack computed pointer |

### Analysis engine details

- **frame reconstruction** scans prologue instructions until the first backward branch or call, which handles delayed setups better than a fixed instruction window
- **CFG construction** builds basic blocks and back-edge relationships instead of relying on flat backward-jump heuristics alone
- **bound matching** only promotes a loop bound into a finding when the compared register is the one actually driving the memory write progression
- **finding deduplication** keys on `(kind, address, section, rationale)` so distinct evidence at one address is preserved
- **bounded-loop suppression** prevents strongly bounded local loops from being reported as suspicious when the proven bound fits the inferred local capacity

### Explicit non-goals

- no decompilation
- no source reconstruction
- no symbolic execution
- no imported-API danger lists turned into fake findings
- no exploitability claims beyond observed disassembly evidence

## Deterministic fixture corpus

`fixtures/` is a dedicated workspace member that builds a separate verification binary containing exact `global_asm!` symbols.

This is a major part of the project’s engineering discipline: analyzer and renderer regressions are validated against precise assembly programs, not compiler-accidental Rust or C code generation.

### What the fixtures provide

- **positive x86_64 fixtures** for every current analyzer finding class
- **negative x86_64 fixtures** for false-positive resistance
- **AArch64 fixtures** for renderer and unsupported-analysis verification
- **linker-retained symbols** through `extern "C"` declarations plus `#[used]` retention tables

### Representative fixture symbols

| Symbol | Expected result |
|---|---|
| `fixture_stack_local_unbounded_loop` | stack-buffer risk + out-of-bounds local write + suspicious copy loop |
| `fixture_stack_oob_write_no_loop` | out-of-bounds local write only |
| `fixture_copy_loop_weak_bound` | suspicious loop / weak-bound behavior without overclaiming stronger proof |
| `fixture_frame_adjacent_write` | unsafe stack-frame write |
| `fixture_indirect_indexed_store` | indirect write risk |
| `fixture_indexed_rsp_write` | stack-pointer / frame-pointer anomaly |
| `fixture_bounded_local_loop` | zero findings |
| `fixture_compare_only_no_write` | zero findings |
| `fixture_frame_setup_no_risky_write` | zero findings |
| `fixture_frame_write_no_setup` | zero findings |
| `fixture_aarch64_basic_function` | zero findings + unsupported-analysis note |

### Fixture workflow

```bash
cargo build -p fixtures
cargo test --test fixtures

# inspect one positive fixture manually
cargo run -- ./target/debug/fixtures --symbol fixture_stack_local_unbounded_loop --analyze --output json
```

### Fixture authoring rules

- symbol names use the `fixture_` prefix
- local labels use `.L_<fixture_name>_<label>`
- every fixture symbol has an explicit `.size` directive for reliable symbol-scoped disassembly
- fixture code lives only in `fixtures/`, never in production `src/`
- fixture verification is Linux/ELF-oriented; AArch64 fixtures are cross-built and disassembled, not executed on the host

## Reverse-engineering example

`examples/password-login/` contains a small C target compiled to preserve readable machine code.

```bash
gcc -O0 -g -fno-inline -fno-builtin -no-pie \
  -o examples/password-login/secret_login \
  examples/password-login/secret_login.c
```

### Inspect the password check

```bash
cargo run -- examples/password-login/secret_login --symbol check_password --render pretty --color never
```

### Analyze the same symbol

```bash
cargo run -- examples/password-login/secret_login --symbol check_password --analyze --render plain --color never
```

This function is intentionally a **negative analysis case**: it reveals a secret through immediate byte comparisons, but it does not perform the stack-local copy or repeated write behavior required for a memory-safety finding.

See `examples/password-login/README.md` for the full walkthrough.

## Architecture support and limits

| Target | Raw bytes | File-backed | Notes |
|---|---|---|---|
| x86 | yes | yes | Intel syntax default, AT&T optional |
| x86_64 | yes | yes | Intel syntax default, AT&T optional |
| AArch64 | yes | yes | use `--arch aarch64` for raw input |
| ARM | no | yes | explicit `--arch arm` required |
| Thumb | no | yes | explicit `--arch thumb` required; bit0 symbol normalization applied |

Important limits:

- raw-byte mode requires `--arch`
- ARM object files are not silently guessed as ARM vs Thumb
- big-endian object files are explicitly rejected
- semantic analysis currently targets **x86** and **x86_64** only

## Safety and robustness

- terminal-hostile strings are escaped before rendering
- pretty output preserves full instruction text without clipping operands or labels
- raw hex input is capped at **8192 decoded bytes**
- input files must be regular files and are capped at **128 MiB**
- raw mode rejects file-only flags such as `--symbol`, `--section`, and `--all-sections`
- Thumb symbol addresses are normalized so label mapping and slicing remain stable on real ELF symbols
- fixture verification uses explicit symbol retention and `nm` checks instead of assuming the linker kept test-only targets

## Verification

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo build -p fixtures
cargo test
cargo test --test fixtures
bash scripts/smoke.sh
```

CI additionally performs:

- x86_64 fixture symbol verification with `nm`
- AArch64 cross-build verification with `aarch64-linux-gnu-gcc`
- AArch64 fixture symbol verification with `aarch64-linux-gnu-nm`

## Project layout

```text
src/
  main.rs            entry point and output dispatch
  cli.rs             CLI model and argument parsing
  types.rs           shared request/report/instruction data model
  disasm.rs          Capstone integration, object parsing, symbol resolution
  render.rs          text rendering, ANSI styling, operand token classification
  analysis.rs        semantic analyzer, CFG construction, finding model

fixtures/
  src/main.rs        symbol retention tables and fixture module wiring
  src/x86_64.rs      exact x86_64 analyzer fixtures
  src/aarch64.rs     exact AArch64 renderer fixtures

tests/
  cli.rs             CLI integration tests
  fixtures.rs        fixture-driven analyzer regression tests

scripts/
  smoke.sh           quick end-to-end verification

examples/
  password-login/    reverse-engineering demo target
```

## Implementation stack

| Component | Technology |
|---|---|
| Language | Rust 2024 edition |
| Decoder backend | [Capstone](https://github.com/capstone-engine/capstone) via `capstone` crate |
| Object parsing | [`object`](https://crates.io/crates/object) |
| CLI parsing | [`clap`](https://crates.io/crates/clap) derive API |
| Structured output | [`serde`](https://crates.io/crates/serde) + [`serde_json`](https://crates.io/crates/serde_json) |
| Error handling | [`anyhow`](https://crates.io/crates/anyhow) |
| Terminal layout | [`unicode-width`](https://crates.io/crates/unicode-width) |
| Verification fixtures | `global_asm!` + ELF `.size` directives |

## Summary

`assembler` is optimized for the real work of low-level inspection:

- point it at bytes or a binary
- narrow to the symbol or section you care about
- get stable, scriptable disassembly output
- optionally attach conservative semantic findings
- verify the whole stack against deterministic assembly fixtures

If you want a terminal-native disassembler with explicit architecture handling, disciplined output, and analyzer behavior that is tested against exact machine code instead of wishful abstractions, this repository is built for that workflow.
