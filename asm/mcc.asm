; MCC risk lookup.
;
; Public API (System V AMD64):
;   void    mcc_init(void)
;     Initializes the 10 000-entry i16 table. Default 5000 (= 0.5 risk),
;     with 10 challenge overrides. Idempotent. Call once at startup.
;
;   int16_t mcc_risk_i16(const char *mcc4)
;     rdi -> pointer to exactly 4 ASCII digit bytes.
;     Returns the i16 risk in eax (sign-extended).
;     No validation: caller guarantees the four bytes are '0'..'9'.

bits 64
default rel

%include "syscalls.inc"
%include "macros.inc"

; ---------------------------------------------------------------------------
section .bss
align 64
mcc_table:  resw 10000              ; 20 000 B — fits L1d (32 KB on Haswell)

; ---------------------------------------------------------------------------
section .text

global mcc_init
mcc_init:
    cld
    lea     rdi, [mcc_table]
    mov     ax, 5000
    mov     ecx, 10000
    rep     stosw

    mov     word [mcc_table + 5411*2], 1500
    mov     word [mcc_table + 5812*2], 3000
    mov     word [mcc_table + 5912*2], 2000
    mov     word [mcc_table + 5944*2], 4500
    mov     word [mcc_table + 7801*2], 8000
    mov     word [mcc_table + 7802*2], 7500
    mov     word [mcc_table + 7995*2], 8500
    mov     word [mcc_table + 4511*2], 3500
    mov     word [mcc_table + 5311*2], 2500
    mov     word [mcc_table + 5999*2], 5000
    ret

global mcc_risk_i16
mcc_risk_i16:
    movzx   eax, byte [rdi]         ; m[0]
    movzx   ecx, byte [rdi+1]       ; m[1]
    movzx   edx, byte [rdi+2]       ; m[2]
    movzx   r8d, byte [rdi+3]       ; m[3]
    sub     eax, '0'
    sub     ecx, '0'
    sub     edx, '0'
    sub     r8d, '0'
    imul    eax, eax, 1000
    imul    ecx, ecx, 100
    lea     edx, [rdx + rdx*4]      ; edx *= 5
    add     eax, ecx
    lea     eax, [rax + rdx*2]      ; eax += 10*m[2]
    add     eax, r8d                ; eax += m[3]
    lea     rcx, [mcc_table]
    movsx   eax, word [rcx + rax*2]
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
