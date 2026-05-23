; Unit test for mcc.asm. Calls mcc_init, then mcc_risk_i16 on a fixed
; vector table. Exits 0 with "[OK] mcc" on full match, 1 with "[FAIL] mcc"
; on first mismatch.

bits 64
default rel

%include "syscalls.inc"
%include "macros.inc"

extern mcc_init
extern mcc_risk_i16

; ---------------------------------------------------------------------------
section .rodata

msg_ok:         db "[OK] mcc", 10
msg_ok_len      equ $ - msg_ok
msg_fail:       db "[FAIL] mcc", 10
msg_fail_len    equ $ - msg_fail

; Layout per row: 4 bytes ASCII MCC + 2 bytes expected i16 + 2 bytes pad = 8 B.
align 8
tests:
    db "5411"
    dw 1500
    dw 0
    db "5812"
    dw 3000
    dw 0
    db "5912"
    dw 2000
    dw 0
    db "5944"
    dw 4500
    dw 0
    db "7801"
    dw 8000
    dw 0
    db "7802"
    dw 7500
    dw 0
    db "7995"
    dw 8500
    dw 0
    db "4511"
    dw 3500
    dw 0
    db "5311"
    dw 2500
    dw 0
    db "5999"
    dw 5000
    dw 0
    db "1234"                       ; default bucket
    dw 5000
    dw 0
    db "0000"                       ; lower edge
    dw 5000
    dw 0
    db "9999"                       ; upper edge (default)
    dw 5000
    dw 0
tests_end:
N_TESTS equ (tests_end - tests) / 8

; ---------------------------------------------------------------------------
section .text
global _start
_start:
    call    mcc_init

    lea     rbx, [tests]            ; rbx = current row
    mov     r12d, N_TESTS

.loop:
    test    r12d, r12d
    jz      .pass

    mov     rdi, rbx
    call    mcc_risk_i16            ; eax = sign-extended result
    movsx   ecx, word [rbx + 4]
    cmp     eax, ecx
    jne     .fail

    add     rbx, 8
    dec     r12d
    jmp     .loop

.pass:
    mov     edi, STDOUT
    lea     rsi, [msg_ok]
    mov     edx, msg_ok_len
    syscall0 SYS_write
    xor     edi, edi
    syscall0 SYS_exit_group

.fail:
    mov     edi, STDOUT
    lea     rsi, [msg_fail]
    mov     edx, msg_fail_len
    syscall0 SYS_write
    mov     edi, 1
    syscall0 SYS_exit_group

section .note.GNU-stack noalloc noexec nowrite progbits
