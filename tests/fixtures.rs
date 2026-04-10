#[cfg(target_os = "linux")]
mod linux_only {
    use std::{
        ffi::OsString,
        path::{Path, PathBuf},
        process::{Command, Output},
        sync::OnceLock,
    };

    use serde_json::Value;

    static FIXTURE_BINARY_PATH: OnceLock<PathBuf> = OnceLock::new();
    static AARCH64_FIXTURE_BINARY_PATH: OnceLock<Option<PathBuf>> = OnceLock::new();

    fn workspace_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    fn cargo_executable() -> OsString {
        std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"))
    }

    fn fixture_build_command(target: Option<&str>) -> Command {
        let mut command = Command::new(cargo_executable());
        command
            .current_dir(workspace_root())
            .args(["build", "-p", "fixtures"]);
        if let Some(target) = target {
            command.args(["--target", target]);
            if target == "aarch64-unknown-linux-gnu" {
                command.env(
                    "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER",
                    "aarch64-linux-gnu-gcc",
                );
            }
        }
        command
    }

    fn fixture_binary_path_for_target(target: Option<&str>) -> PathBuf {
        let target_dir = std::env::var_os("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| workspace_root().join("target"));
        let binary_name = if cfg!(windows) {
            "fixtures.exe"
        } else {
            "fixtures"
        };

        match target {
            Some(target) => target_dir.join(target).join("debug").join(binary_name),
            None => target_dir.join("debug").join(binary_name),
        }
    }

    fn fixture_binary_path() -> &'static PathBuf {
        FIXTURE_BINARY_PATH.get_or_init(|| {
            let status = fixture_build_command(None)
                .status()
                .expect("failed to invoke cargo build for fixtures");
            assert!(status.success(), "fixture binary build failed");

            fixture_binary_path_for_target(None)
        })
    }

    fn aarch64_fixture_binary_path() -> Option<&'static PathBuf> {
        AARCH64_FIXTURE_BINARY_PATH
            .get_or_init(|| {
                let output = fixture_build_command(Some("aarch64-unknown-linux-gnu"))
                    .output()
                    .expect("failed to invoke cross-target cargo build for fixtures");

                if !output.status.success() {
                    eprintln!(
                        "skipping AArch64 fixture tests because cross build failed\nstdout:\n{}\nstderr:\n{}",
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr)
                    );
                    return None;
                }

                Some(fixture_binary_path_for_target(Some("aarch64-unknown-linux-gnu")))
            })
            .as_ref()
    }

    fn assembler_binary() -> &'static str {
        env!("CARGO_BIN_EXE_assembler")
    }

    fn run_fixture_json(symbol: &str) -> Value {
        run_fixture_json_from_binary(fixture_binary_path(), symbol)
    }

    fn run_fixture_json_from_binary(binary: &Path, symbol: &str) -> Value {
        let output = Command::new(assembler_binary())
            .arg(binary)
            .args(["--symbol", symbol, "--analyze", "--output", "json"])
            .output()
            .expect("failed to run assembler against fixture binary");
        assert_success(&output);
        serde_json::from_slice(&output.stdout).expect("fixture analysis output must be valid JSON")
    }

    fn run_fixture_text_from_binary(binary: &Path, symbol: &str) -> String {
        let output = Command::new(assembler_binary())
            .arg(binary)
            .args(["--symbol", symbol, "--render", "plain", "--color", "never"])
            .output()
            .expect("failed to run assembler text rendering against fixture binary");
        assert_success(&output);
        String::from_utf8(output.stdout).expect("fixture text output must be valid UTF-8")
    }

    fn run_fixture_with_exit_code(symbol: &str) -> Output {
        Command::new(assembler_binary())
            .arg(fixture_binary_path())
            .args([
                "--symbol",
                symbol,
                "--analyze",
                "--analyze-exit-code",
                "--output",
                "json",
            ])
            .output()
            .expect("failed to run assembler with --analyze-exit-code")
    }

    fn assert_success(output: &Output) {
        assert!(
            output.status.success(),
            "command failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn findings(json: &Value) -> &[Value] {
        json.get("analysis")
            .and_then(|analysis| analysis.get("findings"))
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .expect("analysis.findings array must be present")
    }

    fn finding_kinds(json: &Value) -> Vec<&str> {
        findings(json)
            .iter()
            .map(|finding| {
                finding
                    .get("kind")
                    .and_then(Value::as_str)
                    .expect("finding.kind must be a string")
            })
            .collect()
    }

    fn assert_has_finding(json: &Value, kind: &str) {
        assert!(
            finding_kinds(json).iter().any(|actual| actual == &kind),
            "expected finding kind {kind}, got {:?}",
            finding_kinds(json)
        );
    }

    fn assert_no_finding(json: &Value, kind: &str) {
        assert!(
            finding_kinds(json).iter().all(|actual| actual != &kind),
            "did not expect finding kind {kind}, got {:?}",
            finding_kinds(json)
        );
    }

    fn assert_zero_findings(json: &Value) {
        assert!(
            findings(json).is_empty(),
            "expected zero findings, got {:?}",
            finding_kinds(json)
        );
    }

    fn assert_note_contains(json: &Value, needle: &str) {
        let notes = json
            .get("analysis")
            .and_then(|analysis| analysis.get("notes"))
            .and_then(Value::as_array)
            .expect("analysis.notes array must be present");
        assert!(
            notes
                .iter()
                .filter_map(Value::as_str)
                .any(|note| note.contains(needle)),
            "expected note containing {needle:?}, got {:?}",
            notes
        );
    }

    fn assert_symbol_present(path: &Path, symbol: &str) {
        let output = Command::new("nm")
            .arg(path)
            .output()
            .expect("failed to invoke nm");
        assert_success(&output);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains(symbol),
            "expected nm output to contain {symbol}, got:\n{stdout}"
        );
    }

    #[test]
    fn fixture_binary_exports_expected_x86_symbols() {
        let binary = fixture_binary_path();
        assert_symbol_present(binary, "fixture_stack_local_unbounded_loop");
        assert_symbol_present(binary, "fixture_stack_oob_write_no_loop");
        assert_symbol_present(binary, "fixture_copy_loop_weak_bound");
        assert_symbol_present(binary, "fixture_frame_adjacent_write");
        assert_symbol_present(binary, "fixture_indirect_indexed_store");
        assert_symbol_present(binary, "fixture_indexed_rsp_write");
        assert_symbol_present(binary, "fixture_bounded_local_loop");
        assert_symbol_present(binary, "fixture_compare_only_no_write");
        assert_symbol_present(binary, "fixture_frame_setup_no_risky_write");
        assert_symbol_present(binary, "fixture_frame_write_no_setup");
    }

    #[test]
    fn fixture_stack_local_unbounded_loop_reports_expected_findings() {
        let json = run_fixture_json("fixture_stack_local_unbounded_loop");
        assert_has_finding(&json, "PotentialStackBufferWriteRisk");
        assert_has_finding(&json, "PossibleOutOfBoundsLocalWrite");
        assert_has_finding(&json, "SuspiciousCopyLoop");
    }

    #[test]
    fn fixture_stack_oob_write_no_loop_reports_oob_only() {
        let json = run_fixture_json("fixture_stack_oob_write_no_loop");
        assert_has_finding(&json, "PossibleOutOfBoundsLocalWrite");
        assert_no_finding(&json, "SuspiciousCopyLoop");
        assert_no_finding(&json, "PotentialStackBufferWriteRisk");
    }

    #[test]
    fn fixture_copy_loop_weak_bound_reports_loop_without_oob() {
        let json = run_fixture_json("fixture_copy_loop_weak_bound");
        assert_has_finding(&json, "PotentialStackBufferWriteRisk");
        assert_has_finding(&json, "SuspiciousCopyLoop");
        assert_no_finding(&json, "PossibleOutOfBoundsLocalWrite");
    }

    #[test]
    fn fixture_frame_adjacent_write_reports_unsafe_frame_write() {
        let json = run_fixture_json("fixture_frame_adjacent_write");
        assert_has_finding(&json, "UnsafeStackFrameWrite");
    }

    #[test]
    fn fixture_indirect_indexed_store_reports_indirect_write_risk() {
        let json = run_fixture_json("fixture_indirect_indexed_store");
        assert_has_finding(&json, "IndirectWriteRisk");
    }

    #[test]
    fn fixture_indexed_rsp_write_reports_stack_pointer_anomaly() {
        let json = run_fixture_json("fixture_indexed_rsp_write");
        assert_has_finding(&json, "StackPointerFramePointerAnomaly");
    }

    #[test]
    fn fixture_bounded_local_loop_is_not_reported_as_risky() {
        let json = run_fixture_json("fixture_bounded_local_loop");
        assert_zero_findings(&json);
    }

    #[test]
    fn fixture_compare_only_no_write_is_a_negative_case() {
        let json = run_fixture_json("fixture_compare_only_no_write");
        assert_zero_findings(&json);
    }

    #[test]
    fn fixture_frame_setup_no_risky_write_is_a_negative_case() {
        let json = run_fixture_json("fixture_frame_setup_no_risky_write");
        assert_zero_findings(&json);
    }

    #[test]
    fn fixture_frame_write_no_setup_is_a_negative_case() {
        let json = run_fixture_json("fixture_frame_write_no_setup");
        assert_zero_findings(&json);
    }

    #[test]
    fn positive_fixture_returns_non_zero_exit_code_when_requested() {
        let output = run_fixture_with_exit_code("fixture_stack_local_unbounded_loop");
        assert_eq!(output.status.code(), Some(1));
    }

    #[test]
    fn negative_fixture_returns_zero_exit_code_when_requested() {
        let output = run_fixture_with_exit_code("fixture_bounded_local_loop");
        assert_eq!(output.status.code(), Some(0));
    }

    #[test]
    fn aarch64_fixture_reports_unsupported_analysis_note() {
        let Some(binary) = aarch64_fixture_binary_path() else {
            return;
        };

        let json = run_fixture_json_from_binary(binary, "fixture_aarch64_basic_function");
        assert_zero_findings(&json);
        assert_note_contains(&json, "No semantic risk analyzer is currently implemented");
    }

    #[test]
    fn aarch64_fixture_renders_expected_registers_and_mnemonics() {
        let Some(binary) = aarch64_fixture_binary_path() else {
            return;
        };

        let rendered = run_fixture_text_from_binary(binary, "fixture_aarch64_basic_function");
        assert!(rendered.contains("stp"));
        assert!(rendered.contains("ldp"));
        assert!(rendered.contains("x29"));
        assert!(rendered.contains("x30"));
        assert!(rendered.contains("sp"));
    }
}

#[cfg(not(target_os = "linux"))]
#[test]
fn fixtures_are_linux_only() {}
