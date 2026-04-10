#[cfg(target_os = "linux")]
use std::arch::global_asm;

#[cfg(target_os = "linux")]
global_asm!(
    r#"
    .text

    .globl fixture_aarch64_basic_function
    .type fixture_aarch64_basic_function, %function
fixture_aarch64_basic_function:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    add x0, x0, x1
    ldp x29, x30, [sp], #16
    ret
    .size fixture_aarch64_basic_function, .-fixture_aarch64_basic_function

    .globl fixture_aarch64_branch_and_compare
    .type fixture_aarch64_branch_and_compare, %function
fixture_aarch64_branch_and_compare:
    cbz x0, .L_fixture_aarch64_branch_and_compare_skip
    add x0, x0, #1
.L_fixture_aarch64_branch_and_compare_skip:
    ret
    .size fixture_aarch64_branch_and_compare, .-fixture_aarch64_branch_and_compare
    "#
);
