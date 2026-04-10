#[cfg(target_os = "linux")]
use std::arch::global_asm;

#[cfg(target_os = "linux")]
global_asm!(
    r#"
    .text

    .globl fixture_stack_local_unbounded_loop
    .type fixture_stack_local_unbounded_loop, @function
fixture_stack_local_unbounded_loop:
    push rbp
    mov rbp, rsp
    sub rsp, 0x20
    xor eax, eax
.L_fixture_stack_local_unbounded_loop_body:
    mov byte ptr [rbp + rax - 0x10], 0x41
    add rax, 1
    cmp rax, 0x40
    jne .L_fixture_stack_local_unbounded_loop_body
    leave
    ret
    .size fixture_stack_local_unbounded_loop, .-fixture_stack_local_unbounded_loop

    .globl fixture_stack_oob_write_no_loop
    .type fixture_stack_oob_write_no_loop, @function
fixture_stack_oob_write_no_loop:
    push rbp
    mov rbp, rsp
    sub rsp, 0x10
    mov qword ptr [rsp + 0x10], rax
    leave
    ret
    .size fixture_stack_oob_write_no_loop, .-fixture_stack_oob_write_no_loop

    .globl fixture_copy_loop_weak_bound
    .type fixture_copy_loop_weak_bound, @function
fixture_copy_loop_weak_bound:
    push rbp
    mov rbp, rsp
    sub rsp, 0x40
    xor ecx, ecx
    mov al, 0x41
.L_fixture_copy_loop_weak_bound_body:
    mov byte ptr [rbp + rcx - 0x20], al
    inc rcx
    cmp rcx, rdx
    jne .L_fixture_copy_loop_weak_bound_body
    leave
    ret
    .size fixture_copy_loop_weak_bound, .-fixture_copy_loop_weak_bound

    .globl fixture_frame_adjacent_write
    .type fixture_frame_adjacent_write, @function
fixture_frame_adjacent_write:
    push rbp
    mov rbp, rsp
    mov qword ptr [rbp + 0x8], rax
    pop rbp
    ret
    .size fixture_frame_adjacent_write, .-fixture_frame_adjacent_write

    .globl fixture_indirect_indexed_store
    .type fixture_indirect_indexed_store, @function
fixture_indirect_indexed_store:
    mov dword ptr [rdi + rcx * 4], eax
    ret
    .size fixture_indirect_indexed_store, .-fixture_indirect_indexed_store

    .globl fixture_indexed_rsp_write
    .type fixture_indexed_rsp_write, @function
fixture_indexed_rsp_write:
    sub rsp, 0x20
    mov byte ptr [rsp + rcx], 0x41
    add rsp, 0x20
    ret
    .size fixture_indexed_rsp_write, .-fixture_indexed_rsp_write

    .globl fixture_bounded_local_loop
    .type fixture_bounded_local_loop, @function
fixture_bounded_local_loop:
    push rbp
    mov rbp, rsp
    sub rsp, 0x40
    xor eax, eax
.L_fixture_bounded_local_loop_body:
    mov byte ptr [rbp + rax - 0x40], 0x41
    add rax, 1
    cmp rax, 0x40
    jne .L_fixture_bounded_local_loop_body
    leave
    ret
    .size fixture_bounded_local_loop, .-fixture_bounded_local_loop

    .globl fixture_compare_only_no_write
    .type fixture_compare_only_no_write, @function
fixture_compare_only_no_write:
    mov al, byte ptr [rdi]
    cmp al, 0x6f
    jne .L_fixture_compare_only_no_write_fail
    mov eax, 0x1
    ret
.L_fixture_compare_only_no_write_fail:
    xor eax, eax
    ret
    .size fixture_compare_only_no_write, .-fixture_compare_only_no_write

    .globl fixture_frame_setup_no_risky_write
    .type fixture_frame_setup_no_risky_write, @function
fixture_frame_setup_no_risky_write:
    push rbp
    mov rbp, rsp
    sub rsp, 0x10
    mov qword ptr [rbp - 0x8], rdi
    leave
    ret
    .size fixture_frame_setup_no_risky_write, .-fixture_frame_setup_no_risky_write

    .globl fixture_frame_write_no_setup
    .type fixture_frame_write_no_setup, @function
fixture_frame_write_no_setup:
    mov qword ptr [rbp + 0x8], rax
    ret
    .size fixture_frame_write_no_setup, .-fixture_frame_write_no_setup
    "#
);
