; Build the 14-dim i16 query vector from a parsed Request.
;
; Public API (System V AMD64):
;   void vectorize(const Request *r, Query *q)
;     rdi = Request*  (72-byte POD struct, layout below)
;     rsi = Query*    (32-byte aligned, 16 i16 slots; v[14..15] padded to 0)
;
; All 14 features are normalized to [0,1] then quantized to i16 in [0,10000].
; Sentinel -10000 is used for v[5]/v[6] when has_last_tx == 0.
;
; Hot path: called once per request. Calls mcc_risk_i16 once at v[12].

bits 64
default rel

%include "syscalls.inc"
%include "macros.inc"

extern mcc_risk_i16

; ---- Request struct layout (matches Request in parse.h) -------------------
%define REQ_AMOUNT          0
%define REQ_CUSTOMER_AVG    8
%define REQ_MERCHANT_AVG    16
%define REQ_KM_HOME         24
%define REQ_KM_LAST         32
%define REQ_TS              40
%define REQ_LAST_TS         48
%define REQ_INSTALLMENTS    56
%define REQ_TX_COUNT_24H    60
%define REQ_MCC             64
%define REQ_IS_ONLINE       68
%define REQ_CARD_PRESENT    69
%define REQ_HAS_LAST_TX     70
%define REQ_KNOWN_MERCHANT  71

; ---------------------------------------------------------------------------
section .rodata
align 8
c_max_amount:        dq 10000.0
c_max_installments:  dq 12.0
c_amount_vs_avg:     dq 10.0
c_max_minutes:       dq 1440.0
c_max_km:            dq 1000.0
c_max_tx_24h:        dq 20.0
c_max_merchant_avg:  dq 10000.0
c_60:                dq 60.0
c_23:                dq 23.0
c_6:                 dq 6.0
c_one:               dq 1.0
c_scale:             dq 10000.0
c_half:              dq 0.5

; ---------------------------------------------------------------------------
section .text

; ---- CLAMP01_I16 ----------------------------------------------------------
; In:  xmm0 = double x
;      xmm14 = c_scale (10000.0), xmm15 = c_half (0.5)  — preloaded once
;             at vectorize entry so the macro is just maxsd/minsd/FMA/cvt.
; Out: eax  = trunc(clamp(x,0,1) * 10000 + 0.5)   (i.e. round-half-up to i16)
; Clobbers xmm0, xmm1.
%macro CLAMP01_I16 0
    xorpd       xmm1, xmm1
    maxsd       xmm0, xmm1
    movsd       xmm1, [c_one]
    minsd       xmm0, xmm1
    vfmadd213sd xmm0, xmm14, xmm15        ; xmm0 = xmm0 * scale + half  (FMA3)
    cvttsd2si   eax, xmm0
%endmacro

global vectorize
vectorize:
    push    rbx
    push    r12
    push    r13
    push    r14
    sub     rsp, 8                       ; align (4 pushes + 8 + ret = 16-aligned)

    mov     rbx, rdi                     ; rbx = Request*
    mov     r12, rsi                     ; r12 = Query*

    ; Preload CLAMP01_I16 constants into xmm14/xmm15 so the macro fuses
    ; the post-clamp scale+round into a single FMA3 instruction per call.
    ; Saves ~3 cy in the dependency chain (mulsd:5 + addsd:3 → vfmadd:5)
    ; plus 2 memory loads per invocation × 14 invocations = 28 fewer L1d
    ; hits per vectorize.  xmm14/15 are unused elsewhere in this function.
    movsd   xmm14, [c_scale]
    movsd   xmm15, [c_half]

    ; v[0] = clamp01(amount / 10000)
    movsd   xmm0, [rbx + REQ_AMOUNT]
    divsd   xmm0, [c_max_amount]
    CLAMP01_I16
    mov     [r12 + 0*2], ax

    ; v[1] = clamp01(installments / 12)
    xorpd   xmm0, xmm0
    cvtsi2sd xmm0, dword [rbx + REQ_INSTALLMENTS]
    divsd   xmm0, [c_max_installments]
    CLAMP01_I16
    mov     [r12 + 1*2], ax

    ; v[2] = customer_avg > 0 ? clamp01((amount / customer_avg) / 10) : 0
    xorpd   xmm0, xmm0
    ucomisd xmm0, [rbx + REQ_CUSTOMER_AVG]
    jp      .v2_zero                     ; NaN customer_avg → store 0 (defensive)
    jae     .v2_zero                     ; if 0 >= customer_avg, store 0
    movsd   xmm0, [rbx + REQ_AMOUNT]
    divsd   xmm0, [rbx + REQ_CUSTOMER_AVG]
    divsd   xmm0, [c_amount_vs_avg]
    CLAMP01_I16
    mov     [r12 + 2*2], ax
    jmp     .v2_done
.v2_zero:
    mov     word [r12 + 2*2], 0
.v2_done:

    ; --- compute hour ∈ [0,23] and weekday ∈ [0,6] from ts ----------------
    ; days_since = ts / 86400 (signed)
    mov     rax, [rbx + REQ_TS]
    mov     rcx, 86400
    cqo
    idiv    rcx                          ; rax = ts/86400
    ; weekday = ((days_since + 3) % 7 + 7) % 7   (1970-01-01 was Thu = 3)
    add     rax, 3
    mov     rcx, 7
    cqo
    idiv    rcx                          ; rdx = remainder ∈ [-6,6]
    add     edx, 7                       ; edx ∈ [1,13]
    mov     eax, edx
    xor     edx, edx
    mov     ecx, 7
    div     ecx                          ; edx = weekday ∈ [0,6]
    mov     r13d, edx

    ; hour = ((ts/3600) % 24 + 24) % 24
    mov     rax, [rbx + REQ_TS]
    mov     rcx, 3600
    cqo
    idiv    rcx                          ; rax = ts/3600
    mov     rcx, 24
    cqo
    idiv    rcx                          ; rdx ∈ [-23,23]
    add     edx, 24                      ; edx ∈ [1,47]
    mov     eax, edx
    xor     edx, edx
    mov     ecx, 24
    div     ecx                          ; edx = hour ∈ [0,23]
    mov     r14d, edx

    ; v[3] = clamp01(hour / 23)
    xorpd   xmm0, xmm0
    cvtsi2sd xmm0, r14d
    divsd   xmm0, [c_23]
    CLAMP01_I16
    mov     [r12 + 3*2], ax

    ; v[4] = clamp01(weekday / 6)
    xorpd   xmm0, xmm0
    cvtsi2sd xmm0, r13d
    divsd   xmm0, [c_6]
    CLAMP01_I16
    mov     [r12 + 4*2], ax

    ; --- v[5], v[6]: depend on has_last_tx --------------------------------
    cmp     byte [rbx + REQ_HAS_LAST_TX], 0
    je      .no_last_tx

    ; minutes = (ts - last_ts) / 60.0; v[5] = clamp01(minutes / 1440)
    mov     rax, [rbx + REQ_TS]
    sub     rax, [rbx + REQ_LAST_TS]
    xorpd   xmm0, xmm0
    cvtsi2sd xmm0, rax
    divsd   xmm0, [c_60]
    divsd   xmm0, [c_max_minutes]
    CLAMP01_I16
    mov     [r12 + 5*2], ax

    movsd   xmm0, [rbx + REQ_KM_LAST]
    divsd   xmm0, [c_max_km]
    CLAMP01_I16
    mov     [r12 + 6*2], ax
    jmp     .after_last_tx

.no_last_tx:
    mov     word [r12 + 5*2], -SCALE
    mov     word [r12 + 6*2], -SCALE
.after_last_tx:

    ; v[7] = clamp01(km_home / 1000)
    movsd   xmm0, [rbx + REQ_KM_HOME]
    divsd   xmm0, [c_max_km]
    CLAMP01_I16
    mov     [r12 + 7*2], ax

    ; v[8] = clamp01(tx_count_24h / 20)
    xorpd   xmm0, xmm0
    cvtsi2sd xmm0, dword [rbx + REQ_TX_COUNT_24H]
    divsd   xmm0, [c_max_tx_24h]
    CLAMP01_I16
    mov     [r12 + 8*2], ax

    ; v[9] = is_online ? SCALE : 0
    movzx   eax, byte [rbx + REQ_IS_ONLINE]
    imul    eax, eax, SCALE
    mov     [r12 + 9*2], ax

    ; v[10] = card_present ? SCALE : 0
    movzx   eax, byte [rbx + REQ_CARD_PRESENT]
    imul    eax, eax, SCALE
    mov     [r12 + 10*2], ax

    ; v[11] = known_merchant ? 0 : SCALE   (unknown_merchant flag)
    movzx   eax, byte [rbx + REQ_KNOWN_MERCHANT]
    xor     eax, 1
    imul    eax, eax, SCALE
    mov     [r12 + 11*2], ax

    ; v[12] = mcc_risk_i16(&r->mcc)
    lea     rdi, [rbx + REQ_MCC]
    call    mcc_risk_i16
    mov     [r12 + 12*2], ax

    ; v[13] = clamp01(merchant_avg / 10000)
    movsd   xmm0, [rbx + REQ_MERCHANT_AVG]
    divsd   xmm0, [c_max_merchant_avg]
    CLAMP01_I16
    mov     [r12 + 13*2], ax

    ; v[14] = v[15] = 0
    mov     dword [r12 + 14*2], 0

    add     rsp, 8
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
