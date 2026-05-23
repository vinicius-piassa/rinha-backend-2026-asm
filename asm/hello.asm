; Toolchain validator. Build:
;   nasm -felf64 hello.asm -o hello.o && ld -static -o hello hello.o
; Run:
;   ./hello   ; prints "asm-rinha alive\n" and exits 0

bits 64
default rel

%include "syscalls.inc"
%include "macros.inc"

global _start

section .rodata
msg:    db "asm-rinha alive", 10
msg_len equ $ - msg

section .text
_start:
    ; write(STDOUT, msg, msg_len)
    mov     edi, STDOUT
    lea     rsi, [msg]
    mov     edx, msg_len
    syscall0 SYS_write

    ; exit(0)
    xor     edi, edi
    syscall0 SYS_exit

section .note.GNU-stack noalloc noexec nowrite progbits
