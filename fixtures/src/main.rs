#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "x86_64")]
mod x86_64;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
unsafe extern "C" {
    fn fixture_stack_local_unbounded_loop();
    fn fixture_stack_oob_write_no_loop();
    fn fixture_copy_loop_weak_bound();
    fn fixture_frame_adjacent_write();
    fn fixture_indirect_indexed_store();
    fn fixture_indexed_rsp_write();
    fn fixture_bounded_local_loop();
    fn fixture_compare_only_no_write();
    fn fixture_frame_setup_no_risky_write();
    fn fixture_frame_write_no_setup();
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[used]
static RETAINED_X86_64_FIXTURES: [unsafe extern "C" fn(); 10] = [
    fixture_stack_local_unbounded_loop,
    fixture_stack_oob_write_no_loop,
    fixture_copy_loop_weak_bound,
    fixture_frame_adjacent_write,
    fixture_indirect_indexed_store,
    fixture_indexed_rsp_write,
    fixture_bounded_local_loop,
    fixture_compare_only_no_write,
    fixture_frame_setup_no_risky_write,
    fixture_frame_write_no_setup,
];

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
unsafe extern "C" {
    fn fixture_aarch64_basic_function();
    fn fixture_aarch64_branch_and_compare();
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
#[used]
static RETAINED_AARCH64_FIXTURES: [unsafe extern "C" fn(); 2] = [
    fixture_aarch64_basic_function,
    fixture_aarch64_branch_and_compare,
];

fn main() {}
