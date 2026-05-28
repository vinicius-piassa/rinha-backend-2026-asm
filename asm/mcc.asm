; MCC risk lookup.
;
; Public API (System V AMD64):
;   void    mcc_init(void)
;     No-op now (kept for ABI compatibility).  Override tables are static
;     .rodata; no init step required.
;
;   int16_t mcc_risk_i16(const char *mcc4)
;     rdi -> pointer to exactly 4 ASCII digit bytes.
;     Returns the i16 risk in eax (sign-extended).
;     No validation: caller guarantees the four bytes are '0'..'9'.
;
; Implementation: the prior 20 KB i16-by-MCC table was ~63% of Haswell L1d
; and got touched at most once per request — cold-line eviction pressure on
; everything else (top-K state, pair_base, msgpool).  Replaced with a 64-B
; (one cache line) AVX2 compare against 9 real overrides + default 5000.

bits 64
default rel

%include "syscalls.inc"
%include "macros.inc"

; ---------------------------------------------------------------------------
section .rodata
align 32
; 16 × u16 = 32 B = one ymm.  Real overrides are the first 9 entries; the
; rest are sentinels 0xFFFF (> max valid MCC 9999) that never match.
override_keys:
    dw  5411, 5812, 5912, 5944, 7801, 7802, 7995, 4511
    dw  5311, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF

align 32
override_vals:
    dw  1500, 3000, 2000, 4500, 8000, 7500, 8500, 3500
    dw  2500,    0,    0,    0,    0,    0,    0,    0

; ---------------------------------------------------------------------------
section .text

global mcc_init
mcc_init:
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
    add     eax, r8d                ; eax = MCC (0..9999)

    ; AVX2 broadcast-compare against 16-entry override table.
    vmovd        xmm0, eax
    vpbroadcastw ymm0, xmm0
    vmovdqa      ymm1, [override_keys]
    vpcmpeqw     ymm0, ymm0, ymm1
    vpmovmskb    eax, ymm0
    test         eax, eax
    jz           .default
    tzcnt        eax, eax
    shr          eax, 1              ; byte-pos → u16 index
    lea          rcx, [override_vals]
    movsx        eax, word [rcx + rax*2]
    vzeroupper                       ; clear ymm INIT bit before returning
    ret
.default:
    mov          eax, 5000
    vzeroupper                       ; clear ymm INIT bit before returning
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
