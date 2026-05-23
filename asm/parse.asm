; Scalar JSON / ISO8601 / numeric primitives for the request parser.
;
; Calling convention: System V AMD64.  Helpers that consume a (p, end) cursor
; return the updated p in rax; they read inputs through their first args and
; write outputs through pointer args.  None of the helpers allocate.
;
; This file delivers:
;   6a -- skip_ws, parse_uint64, parse_int32, parse_number, parse_iso8601
;   6b -- skip_string_body, skip_value, key_eq, buf_contains, read_key, after_value
;   6c -- parse_transaction / parse_customer / parse_merchant / parse_terminal /
;         parse_last_tx + the public entry parse_request.

bits 64
default rel

%include "syscalls.inc"
%include "macros.inc"

; Request struct field offsets — kept in sync with vectorize.asm consumers.
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
; Inverse powers of 10, indexed by fractional-digit count [0..19].
pow10_neg:
    dq 1.0,    1e-1,  1e-2,  1e-3,  1e-4,  1e-5,  1e-6,  1e-7
    dq 1e-8,   1e-9,  1e-10, 1e-11, 1e-12, 1e-13, 1e-14, 1e-15
    dq 1e-16,  1e-17, 1e-18, 1e-19

c_one_double:  dq 1.0
c_ten_double:  dq 10.0
c_negzero:     dq 0x8000000000000000   ; bit pattern of -0.0 (sign bit only)

; Key string literals.  No null terminators; lengths are explicit.
str_amount:        db "amount"
str_installments:  db "installments"
str_requested_at:  db "requested_at"
str_avg_amount:    db "avg_amount"
str_tx_count_24h:  db "tx_count_24h"
str_known_merch:   db "known_merchants"
str_id:            db "id"
str_mcc:           db "mcc"
str_is_online:     db "is_online"
str_card_present:  db "card_present"
str_km_from_home:  db "km_from_home"
str_timestamp:     db "timestamp"
str_km_from_curr:  db "km_from_current"
str_transaction:   db "transaction"
str_customer:      db "customer"
str_merchant:      db "merchant"
str_terminal:      db "terminal"
str_last_tx:       db "last_transaction"

; ---------------------------------------------------------------------------
section .text

; ---- skip_ws --------------------------------------------------------------
; const char *skip_ws(const char *p, const char *end);
;   rdi = p, rsi = end → rax = updated p
;
; JSON whitespace: SP (0x20), HT (0x09), LF (0x0A), CR (0x0D).

global skip_ws
skip_ws:
.loop:
    cmp     rdi, rsi
    jae     .done
    movzx   eax, byte [rdi]
    cmp     al, ' '
    je      .skip
    cmp     al, 9
    je      .skip
    cmp     al, 10
    je      .skip
    cmp     al, 13
    jne     .done
.skip:
    inc     rdi
    jmp     .loop
.done:
    mov     rax, rdi
    ret

; ---- parse_uint64 --------------------------------------------------------
; const char *parse_uint64(const char *p, const char *end, uint64_t *out);
;   rdi = p, rsi = end, rdx = out → rax = updated p
;
; Greedy digit run: stops at first non-digit or end.  No overflow check
; (caller-domain values fit easily within u64).

global parse_uint64
parse_uint64:
    xor     ecx, ecx                   ; v = 0
.loop:
    cmp     rdi, rsi
    jae     .done
    movzx   eax, byte [rdi]
    sub     eax, '0'
    cmp     eax, 9
    ja      .done                      ; unsigned: < 0 or > 9 → not a digit
    lea     rcx, [rcx + rcx*4]         ; v *= 5
    lea     rcx, [rax + rcx*2]         ; v = digit + 2*v  → 10*v + digit
    inc     rdi
    jmp     .loop
.done:
    mov     [rdx], rcx
    mov     rax, rdi
    ret

; ---- parse_int32 ---------------------------------------------------------
; const char *parse_int32(const char *p, const char *end, int32_t *out);
;   rdi = p, rsi = end, rdx = out → rax = updated p

global parse_int32
parse_int32:
    push    rbx                        ; save (1 push)
    push    rbp                        ; (2)
    push    r12                        ; (3)
    push    r13                        ; (4)
    sub     rsp, 24                    ; entry rsp=8 mod16; 4 push=-32 mod16=8; sub24→ -56 mod16=8.  NOT aligned.
    ; Fix alignment: we call parse_uint64, which needs 16-aligned rsp at call site.
    ; After 4 pushes + sub 24 → rsp ≡ 8 mod 16.  CALL pushes 8 → callee sees mod16=0, which is wrong for SysV (expects 8).
    ; Wait — SysV says rsp before CALL must be 16-aligned (multiple of 16), call pushes 8, callee enters with rsp≡8.  So we need rsp ≡ 0 mod 16 before call.
    ; Need: 4 push + sub N where N ≡ 0 mod 16.  4*8=32 → mod16 = 0 → after pushes rsp ≡ 8.  So N must make rsp drop by another (8 mod 16), i.e., N mod 16 = 8.  Try N=24:  rsp ≡ 8-24 mod 16 = -16 mod 16 = 0 ✓.  Hmm let me redo:
    ; rsp at entry (after CALL pushed ret addr): rsp_init ≡ 8 mod 16.
    ; After 4 pushes (-32 bytes): rsp ≡ 8 - 32 = -24 ≡ 8 mod 16.
    ; After sub 24: rsp ≡ 8 - 24 = -16 ≡ 0 mod 16. ✓
    ; OK so sub 24 IS correct.  My comment above was wrong.  Verified.

    mov     rbx, rdi                   ; p
    mov     rbp, rsi                   ; end
    mov     r12, rdx                   ; out (int32_t*)

    xor     r13d, r13d                 ; neg = 0
    cmp     rbx, rbp
    jae     .digits
    cmp     byte [rbx], '-'
    jne     .digits
    mov     r13d, 1
    inc     rbx

.digits:
    mov     rdi, rbx
    mov     rsi, rbp
    lea     rdx, [rsp]                 ; u64 scratch
    call    parse_uint64               ; rax = new p

    mov     ecx, [rsp]                 ; low 32 bits of v
    test    r13d, r13d
    jz      .pos
    neg     ecx
.pos:
    mov     [r12], ecx                 ; rax (new p) unchanged

    add     rsp, 24
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret

; ---- parse_number --------------------------------------------------------
; const char *parse_number(const char *p, const char *end, double *out);
;   rdi = p, rsi = end, rdx = out → rax = updated p
;
; Sign + integer + optional fractional (lookup pow10_neg[len], len < 20) +
; optional exponent (e/E, optional ±, decimal digits → iterative *=10.0).
;
; Stack locals (allocated 40 B; aligns rsp to 16 before nested calls):
;   [rsp +  0] int_part u64
;   [rsp +  8] frac u64
;   [rsp + 16] e u64
;   [rsp + 24] v double (running result; survives parse_uint64 calls)

global parse_number
parse_number:
    push    rbx                        ; (1) p
    push    rbp                        ; (2) end
    push    r12                        ; (3) out
    push    r13                        ; (4) neg
    push    r14                        ; (5) eneg
    push    r15                        ; (6) frac_len / scratch
    sub     rsp, 40
    ; rsp ≡ 8 - 48 - 40 = -80 ≡ 0 mod 16 ✓

    mov     rbx, rdi
    mov     rbp, rsi
    mov     r12, rdx

    xor     r13d, r13d                 ; neg = 0
    cmp     rbx, rbp
    jae     .int
    cmp     byte [rbx], '-'
    jne     .int
    mov     r13d, 1
    inc     rbx

.int:
    mov     rdi, rbx
    mov     rsi, rbp
    lea     rdx, [rsp]
    call    parse_uint64
    mov     rbx, rax
    cvtsi2sd xmm0, qword [rsp]         ; v = (double)int_part
    movsd   [rsp + 24], xmm0

    ; Optional fractional
    cmp     rbx, rbp
    jae     .check_exp
    cmp     byte [rbx], '.'
    jne     .check_exp

    inc     rbx
    mov     r14, rbx                   ; (reuse r14 briefly as frac_start)
    mov     rdi, rbx
    mov     rsi, rbp
    lea     rdx, [rsp + 8]
    call    parse_uint64
    mov     rbx, rax

    mov     r15, rbx
    sub     r15, r14                   ; len = p - frac_start
    cmp     r15, 20
    jae     .check_exp                 ; bail: C drops len >= 20

    cvtsi2sd xmm0, qword [rsp + 8]
    lea     rax, [pow10_neg]
    mulsd   xmm0, [rax + r15*8]
    addsd   xmm0, [rsp + 24]
    movsd   [rsp + 24], xmm0

.check_exp:
    cmp     rbx, rbp
    jae     .apply_sign
    movzx   eax, byte [rbx]
    cmp     al, 'e'
    je      .exp
    cmp     al, 'E'
    jne     .apply_sign

.exp:
    inc     rbx
    xor     r14d, r14d                 ; eneg
    cmp     rbx, rbp
    jae     .exp_digits
    movzx   eax, byte [rbx]
    cmp     al, '+'
    je      .exp_skip_sign
    cmp     al, '-'
    jne     .exp_digits
    mov     r14d, 1
.exp_skip_sign:
    inc     rbx

.exp_digits:
    mov     rdi, rbx
    mov     rsi, rbp
    lea     rdx, [rsp + 16]
    call    parse_uint64
    mov     rbx, rax

    ; s = 10^e via iterative mulsd (e small in practice)
    movsd   xmm1, [c_one_double]
    mov     rcx, [rsp + 16]
    test    rcx, rcx
    jz      .apply_exp
.exp_mul_loop:
    mulsd   xmm1, [c_ten_double]
    dec     rcx
    jnz     .exp_mul_loop

.apply_exp:
    movsd   xmm0, [rsp + 24]
    test    r14d, r14d
    jz      .apply_exp_mul
    divsd   xmm0, xmm1
    jmp     .save_v
.apply_exp_mul:
    mulsd   xmm0, xmm1
.save_v:
    movsd   [rsp + 24], xmm0

.apply_sign:
    movsd   xmm0, [rsp + 24]
    test    r13d, r13d
    jz      .store
    movsd   xmm1, [c_negzero]
    xorpd   xmm0, xmm1                 ; flip sign bit (matches `v = -v`)

.store:
    movsd   [r12], xmm0
    mov     rax, rbx

    add     rsp, 40
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret

; ---- parse_iso8601 -------------------------------------------------------
; int64_t parse_iso8601(const char *s, int len);
;   rdi = s, esi = len
;   returns rax = epoch seconds (UTC) or 0 if len < 19
;
; Format: "YYYY-MM-DDThh:mm:ss[.fff][Z|+HH:MM]"  (only first 19 bytes used)
; Uses Howard Hinnant's days_from_civil algorithm; ignores trailing fraction
; and timezone offset.
;
; Stack locals (16 B, 16-aligned via push rbx + push rbp + sub 16):
;   [rsp +  0] sec  u32  (no, we only use up to 3 bytes)
;   [rsp +  4] mn
;   [rsp +  8] hour
;   [rsp + 12] -- unused

global parse_iso8601
parse_iso8601:
    xor     eax, eax
    cmp     esi, 19
    jl      .ret

    push    rbx
    push    rbp
    sub     rsp, 16
    ; entry rsp=8; 2 push=-16 → 8; sub16→ -32 ≡ 0 ✓ (we make no calls anyway)

    ; year = (s[0]-'0')*1000 + (s[1]-'0')*100 + (s[2]-'0')*10 + (s[3]-'0')
    movzx   r8d,  byte [rdi]
    movzx   r9d,  byte [rdi + 1]
    movzx   r10d, byte [rdi + 2]
    movzx   r11d, byte [rdi + 3]
    sub     r8d,  '0'
    sub     r9d,  '0'
    sub     r10d, '0'
    sub     r11d, '0'
    imul    r8d,  r8d, 1000
    imul    r9d,  r9d, 100
    lea     r10d, [r10d + r10d*4]      ; *5
    add     r8d, r9d
    lea     r8d, [r8d + r10d*2]        ; + 10*s[2]
    add     r8d, r11d                  ; + s[3]
    ; r8d = year

    ; month = (s[5]-'0')*10 + (s[6]-'0')
    movzx   r9d,  byte [rdi + 5]
    movzx   r10d, byte [rdi + 6]
    sub     r9d,  '0'
    sub     r10d, '0'
    lea     r9d,  [r9d + r9d*4]
    lea     r9d,  [r10d + r9d*2]
    ; r9d = month

    ; day = (s[8]-'0')*10 + (s[9]-'0')
    movzx   r10d, byte [rdi + 8]
    movzx   r11d, byte [rdi + 9]
    sub     r10d, '0'
    sub     r11d, '0'
    lea     r10d, [r10d + r10d*4]
    lea     r10d, [r11d + r10d*2]
    ; r10d = day

    ; hour, mn, sec → stack (free up regs for the days_from_civil math)
    movzx   eax,  byte [rdi + 11]
    movzx   ecx,  byte [rdi + 12]
    sub     eax,  '0'
    sub     ecx,  '0'
    lea     eax,  [rax + rax*4]
    lea     eax,  [rcx + rax*2]
    mov     [rsp + 8], eax             ; hour

    movzx   eax,  byte [rdi + 14]
    movzx   ecx,  byte [rdi + 15]
    sub     eax,  '0'
    sub     ecx,  '0'
    lea     eax,  [rax + rax*4]
    lea     eax,  [rcx + rax*2]
    mov     [rsp + 4], eax             ; mn

    movzx   eax,  byte [rdi + 17]
    movzx   ecx,  byte [rdi + 18]
    sub     eax,  '0'
    sub     ecx,  '0'
    lea     eax,  [rax + rax*4]
    lea     eax,  [rcx + rax*2]
    mov     [rsp + 0], eax             ; sec

    ; --- days_from_civil ---------------------------------------------------
    ; y = year - (month <= 2 ? 1 : 0)
    xor     ecx, ecx
    cmp     r9d, 2
    setle   cl
    sub     r8d, ecx                   ; y in r8d

    ; era = (y >= 0 ? y : y - 399) / 400
    mov     eax, r8d
    test    eax, eax
    jns     .era_pos
    sub     eax, 399
.era_pos:
    cdq
    mov     ecx, 400
    idiv    ecx                        ; eax = era
    mov     r11d, eax                  ; r11d = era

    ; yoe = y - era*400
    imul    eax, eax, 400
    sub     r8d, eax                   ; r8d = yoe (0..399)

    ; m = month > 2 ? month - 3 : month + 9
    cmp     r9d, 2
    jg      .m_gt2
    add     r9d, 9
    jmp     .m_done
.m_gt2:
    sub     r9d, 3
.m_done:                                ; r9d = m

    ; doy = (153*m + 2)/5 + day - 1
    imul    r9d, r9d, 153
    add     r9d, 2
    mov     eax, r9d
    cdq
    mov     ecx, 5
    idiv    ecx                        ; eax = (153m+2)/5
    add     eax, r10d                  ; + day
    dec     eax                        ; - 1
    mov     ebx, eax                   ; ebx = doy

    ; doe = yoe*365 + yoe/4 - yoe/100 + doy
    mov     eax, r8d
    imul    eax, eax, 365              ; yoe*365
    mov     ecx, r8d
    sar     ecx, 2                     ; yoe/4 (yoe ≥ 0, but sar matches signed div semantics)
    add     eax, ecx                   ; partial
    mov     ebp, eax                   ; ebp = yoe*365 + yoe/4
    mov     eax, r8d
    cdq
    mov     ecx, 100
    idiv    ecx                        ; eax = yoe/100
    sub     ebp, eax                   ; - yoe/100
    add     ebp, ebx                   ; + doy → ebp = doe

    ; days = era*146097 + doe - 719468 (i64)
    movsxd  rcx, r11d                  ; era as i64
    imul    rcx, rcx, 146097
    movsxd  rax, ebp                   ; doe as i64
    add     rax, rcx
    sub     rax, 719468

    ; epoch = days*86400 + hour*3600 + mn*60 + sec
    imul    rax, rax, 86400
    mov     ecx, [rsp + 8]
    imul    rcx, rcx, 3600
    add     rax, rcx
    mov     ecx, [rsp + 4]
    imul    rcx, rcx, 60
    add     rax, rcx
    mov     ecx, [rsp + 0]
    add     rax, rcx

    add     rsp, 16
    pop     rbp
    pop     rbx
.ret:
    ret

; ---- skip_string_body -----------------------------------------------------
; const char *skip_string_body(const char *p, const char *end);
;   rdi = p (positioned just past opening '"'), rsi = end → rax = p past closing '"'
;
; Handles \\ escape (skips 2 bytes).  Returns `end` if no closing quote found.

global skip_string_body
skip_string_body:
.loop:
    cmp     rdi, rsi
    jae     .end_of_buf
    movzx   eax, byte [rdi]
    cmp     al, '"'
    je      .found
    cmp     al, 0x5C                   ; backslash
    jne     .plain
    add     rdi, 2                     ; skip escape + following byte
    jmp     .loop
.plain:
    inc     rdi
    jmp     .loop
.found:
    lea     rax, [rdi + 1]
    ret
.end_of_buf:
    mov     rax, rsi
    ret

; ---- skip_value -----------------------------------------------------------
; const char *skip_value(const char *p, const char *end);
;   rdi = p, rsi = end → rax = p past the value
;
; Branches: string (tail-call skip_string_body), '{...}'/'[...]' (depth-tracked
; walk with embedded string skipping), or scalar (read until structural/ws).

global skip_value
skip_value:
    cmp     rdi, rsi
    jae     .ret_p
    movzx   eax, byte [rdi]
    cmp     al, '"'
    je      .str
    cmp     al, '{'
    je      .open_obj
    cmp     al, '['
    je      .open_arr

.scalar:
    cmp     rdi, rsi
    jae     .ret_p
    movzx   eax, byte [rdi]
    cmp     al, ','
    je      .ret_p
    cmp     al, '}'
    je      .ret_p
    cmp     al, ']'
    je      .ret_p
    cmp     al, ' '
    je      .ret_p
    cmp     al, 9
    je      .ret_p
    cmp     al, 10
    je      .ret_p
    cmp     al, 13
    je      .ret_p
    inc     rdi
    jmp     .scalar

.ret_p:
    mov     rax, rdi
    ret

.str:
    inc     rdi
    jmp     skip_string_body            ; tail call

.open_obj:
    push    rbx                          ; 4 pushes + sub 8 brings rsp to 0 mod 16
    push    r12
    push    r13
    push    r14
    sub     rsp, 8
    mov     r13d, '{'
    mov     r14d, '}'
    jmp     .c_init
.open_arr:
    push    rbx
    push    r12
    push    r13
    push    r14
    sub     rsp, 8
    mov     r13d, '['
    mov     r14d, ']'

.c_init:
    mov     rbx, rsi                     ; end (callee-save)
    mov     r12d, 1                      ; depth
    inc     rdi
.c_loop:
    cmp     rdi, rbx
    jae     .c_done
    test    r12d, r12d
    jz      .c_done
    movzx   eax, byte [rdi]
    cmp     eax, '"'
    je      .c_str
    cmp     eax, r13d                    ; open
    je      .c_open
    cmp     eax, r14d                    ; close
    je      .c_close
    inc     rdi
    jmp     .c_loop
.c_str:
    inc     rdi
    mov     rsi, rbx
    call    skip_string_body
    mov     rdi, rax
    jmp     .c_loop
.c_open:
    inc     r12d
    inc     rdi
    jmp     .c_loop
.c_close:
    dec     r12d
    inc     rdi
    jmp     .c_loop
.c_done:
    mov     rax, rdi
    add     rsp, 8
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret

; ---- key_eq ---------------------------------------------------------------
; bool key_eq(const char *k, int kl, const char *lit, int ll);
;   rdi=k, esi=kl, rdx=lit, ecx=ll → eax = 1 if (kl==ll && bytes match) else 0

global key_eq
key_eq:
    cmp     esi, ecx
    jne     .no
    test    ecx, ecx
    jz      .yes
.cmp:
    movzx   eax, byte [rdi]
    movzx   r8d, byte [rdx]
    cmp     eax, r8d
    jne     .no
    inc     rdi
    inc     rdx
    dec     ecx
    jnz     .cmp
.yes:
    mov     eax, 1
    ret
.no:
    xor     eax, eax
    ret

; ---- buf_contains ---------------------------------------------------------
; bool buf_contains(const char *hay, size_t hl, const char *nd, size_t nl);
;   rdi=hay, rsi=hl, rdx=nd, rcx=nl → eax = 1/0
;
; Linear scan with first-byte filter; no SIMD (needles are short).

global buf_contains
buf_contains:
    test    rcx, rcx
    jz      .no
    cmp     rcx, rsi
    ja      .no

    push    rbx
    push    rbp
    push    r12
    push    r13

    movzx   r13d, byte [rdx]            ; first byte of needle
    mov     rbp, rdx                    ; nd
    mov     r12, rcx                    ; nl
    add     rsi, rdi                    ; hay + hl
    sub     rsi, rcx                    ; - nl
    inc     rsi                         ; + 1 = end_p
    mov     rbx, rsi

.scan:
    cmp     rdi, rbx
    jae     .miss
    movzx   eax, byte [rdi]
    cmp     eax, r13d
    jne     .next
    ; full byte compare over r12 bytes from rdi vs rbp
    mov     r8, r12
    mov     r9, rdi
    mov     r10, rbp
.mcmp:
    movzx   eax, byte [r9]
    movzx   ecx, byte [r10]
    cmp     eax, ecx
    jne     .next
    inc     r9
    inc     r10
    dec     r8
    jnz     .mcmp
    mov     eax, 1
    jmp     .ret

.next:
    inc     rdi
    jmp     .scan

.miss:
    xor     eax, eax
.ret:
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret

.no:
    xor     eax, eax
    ret

; ---- read_key -------------------------------------------------------------
; const char *read_key(const char *p, const char *end,
;                      const char **kp, int *kl);
;   rdi=p, rsi=end, rdx=kp, rcx=kl
;   returns rax = p past the colon and following ws, or 0 (NULL) on parse error

global read_key
read_key:
    push    rbx                         ; p
    push    rbp                         ; end
    push    r12                         ; kp
    push    r13                         ; kl
    sub     rsp, 8                       ; align (4 push=0 mod16; sub 8 = 8 → wrong)
    ; actually entry rsp=8, 4 push=-32 → 8 mod16, sub 8 → 0 mod16 ✓

    mov     rbx, rdi
    mov     rbp, rsi
    mov     r12, rdx
    mov     r13, rcx

    ; p = skip_ws(p, end)
    mov     rdi, rbx
    mov     rsi, rbp
    call    skip_ws
    mov     rbx, rax

    cmp     rbx, rbp
    jae     .fail
    cmp     byte [rbx], '"'
    jne     .fail
    inc     rbx                          ; past opening quote
    mov     [r12], rbx                   ; *kp = rbx

    ; scan to closing quote
    mov     rax, rbx
.scan:
    cmp     rax, rbp
    jae     .fail
    cmp     byte [rax], '"'
    je      .got_close
    inc     rax
    jmp     .scan
.got_close:
    sub     rax, rbx                     ; key length
    mov     [r13], eax                   ; *kl = length (i32 store)
    add     rbx, rax
    inc     rbx                          ; past closing quote

    mov     rdi, rbx
    mov     rsi, rbp
    call    skip_ws
    mov     rbx, rax

    cmp     rbx, rbp
    jae     .fail
    cmp     byte [rbx], ':'
    jne     .fail
    inc     rbx

    mov     rdi, rbx
    mov     rsi, rbp
    call    skip_ws
    ; rax holds the return; fall through to .ret
    jmp     .ret

.fail:
    xor     eax, eax
.ret:
    add     rsp, 8
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret

; ---- after_value ----------------------------------------------------------
; const char *after_value(const char *p, const char *end);
;   rdi=p, rsi=end → rax = next iter p (past optional comma, ws-skipped)

global after_value
after_value:
    push    rbx                          ; 1 push: rsp 0 mod 16 ✓ (no locals needed)
    mov     rbx, rsi                     ; end
    call    skip_ws
    cmp     rax, rbx
    jae     .done
    cmp     byte [rax], ','
    jne     .done
    inc     rax
    mov     rdi, rax
    mov     rsi, rbx
    call    skip_ws
.done:
    pop     rbx
    ret

; ===========================================================================
; 6c -- Sub-object parsers + parse_request
; ===========================================================================
;
; Common stack layout for sub-parsers (3 pushes + sub 32 → rsp 0 mod 16):
;   [rsp +  0..7]   k (const char *)
;   [rsp +  8..11]  kl (int)
;   [rsp + 12..15]  pad
;   [rsp + 16..23]  scratch1
;   [rsp + 24..31]  scratch2
;
; TRY_KEY macro: tests if the captured (k, kl) at [rsp + 0]/[rsp + 8] matches
; a literal of given length; jumps to handler on match.

%macro TRY_KEY 3   ; %1 = literal symbol, %2 = length, %3 = handler label
    mov     rdi, [rsp + 0]
    mov     esi, [rsp + 8]
    lea     rdx, [%1]
    mov     ecx, %2
    call    key_eq
    test    eax, eax
    jnz     %3
%endmacro

; Copy one MCC byte at offset I (0..3), padding with '0' if I >= n (ecx).
; rdi = source ptr s, r12 = Request*.
%macro COPY_MCC_BYTE 1
    mov     al, '0'
    cmp     ecx, %1
    jle     %%pad
    mov     al, [rdi + %1]
%%pad:
    mov     [r12 + REQ_MCC + %1], al
%endmacro

; ---- parse_transaction ---------------------------------------------------
; const char *parse_transaction(const char *p, const char *end, Request *r);

global parse_transaction
parse_transaction:
    push    rbx                          ; p
    push    rbp                          ; end
    push    r12                          ; out
    sub     rsp, 32

    mov     rbx, rdi
    mov     rbp, rsi
    mov     r12, rdx

    cmp     rbx, rbp
    jae     .fail
    cmp     byte [rbx], '{'
    jne     .fail
    inc     rbx
    mov     rdi, rbx
    mov     rsi, rbp
    call    skip_ws
    mov     rbx, rax

.loop:
    cmp     rbx, rbp
    jae     .fail
    cmp     byte [rbx], '}'
    je      .end_obj

    mov     rdi, rbx
    mov     rsi, rbp
    lea     rdx, [rsp + 0]
    lea     rcx, [rsp + 8]
    call    read_key
    test    rax, rax
    jz      .fail
    mov     rbx, rax

    TRY_KEY str_amount,       6,  .h_amount
    TRY_KEY str_installments, 12, .h_installments
    TRY_KEY str_requested_at, 12, .h_requested_at

    ; Unknown key -> skip_value
    mov     rdi, rbx
    mov     rsi, rbp
    call    skip_value
    mov     rbx, rax
    jmp     .after

.h_amount:
    mov     rdi, rbx
    mov     rsi, rbp
    lea     rdx, [r12 + REQ_AMOUNT]
    call    parse_number
    mov     rbx, rax
    jmp     .after

.h_installments:
    mov     rdi, rbx
    mov     rsi, rbp
    lea     rdx, [r12 + REQ_INSTALLMENTS]
    call    parse_int32
    mov     rbx, rax
    jmp     .after

.h_requested_at:
    cmp     rbx, rbp
    jae     .fail
    cmp     byte [rbx], '"'
    jne     .fail
    lea     rdi, [rbx + 1]               ; s
    mov     [rsp + 16], rdi              ; stash s
    mov     rsi, rbp
    call    skip_string_body             ; rax = q
    mov     [rsp + 24], rax              ; stash q
    ; len = q - 1 - s
    mov     rcx, rax
    sub     rcx, [rsp + 16]
    dec     rcx                          ; rcx = len
    mov     rdi, [rsp + 16]              ; s
    mov     esi, ecx                     ; len as i32
    call    parse_iso8601
    mov     [r12 + REQ_TS], rax
    mov     rbx, [rsp + 24]              ; p = q
    jmp     .after

.after:
    mov     rdi, rbx
    mov     rsi, rbp
    call    after_value
    mov     rbx, rax
    jmp     .loop

.end_obj:
    lea     rax, [rbx + 1]
    add     rsp, 32
    pop     r12
    pop     rbp
    pop     rbx
    ret

.fail:
    xor     eax, eax
    add     rsp, 32
    pop     r12
    pop     rbp
    pop     rbx
    ret

; ---- parse_customer ------------------------------------------------------
; const char *parse_customer(const char *p, const char *end, Request *r,
;                            const char **km_start, const char **km_end);
;   rdi, rsi, rdx, rcx, r8

global parse_customer
parse_customer:
    push    rbx
    push    rbp
    push    r12                          ; out
    push    r13                          ; km_start ptr
    push    r14                          ; km_end ptr
    sub     rsp, 16                       ; locals (8 for k, 4 kl + pad).  5 push + 16 → mod16=0

    mov     rbx, rdi
    mov     rbp, rsi
    mov     r12, rdx
    mov     r13, rcx
    mov     r14, r8

    cmp     rbx, rbp
    jae     .fail
    cmp     byte [rbx], '{'
    jne     .fail
    inc     rbx
    mov     rdi, rbx
    mov     rsi, rbp
    call    skip_ws
    mov     rbx, rax

.loop:
    cmp     rbx, rbp
    jae     .fail
    cmp     byte [rbx], '}'
    je      .end_obj

    mov     rdi, rbx
    mov     rsi, rbp
    lea     rdx, [rsp + 0]
    lea     rcx, [rsp + 8]
    call    read_key
    test    rax, rax
    jz      .fail
    mov     rbx, rax

    TRY_KEY str_avg_amount,   10, .h_avg
    TRY_KEY str_tx_count_24h, 12, .h_txc
    TRY_KEY str_known_merch,  15, .h_km

    mov     rdi, rbx
    mov     rsi, rbp
    call    skip_value
    mov     rbx, rax
    jmp     .after

.h_avg:
    mov     rdi, rbx
    mov     rsi, rbp
    lea     rdx, [r12 + REQ_CUSTOMER_AVG]
    call    parse_number
    mov     rbx, rax
    jmp     .after

.h_txc:
    mov     rdi, rbx
    mov     rsi, rbp
    lea     rdx, [r12 + REQ_TX_COUNT_24H]
    call    parse_int32
    mov     rbx, rax
    jmp     .after

.h_km:
    cmp     rbx, rbp
    jae     .fail
    cmp     byte [rbx], '['
    jne     .fail
    mov     [r13], rbx                   ; *km_start = p (pointing at '[')
    mov     rdi, rbx
    mov     rsi, rbp
    call    skip_value
    mov     rbx, rax
    mov     [r14], rbx                   ; *km_end = p (just past ']')
    jmp     .after

.after:
    mov     rdi, rbx
    mov     rsi, rbp
    call    after_value
    mov     rbx, rax
    jmp     .loop

.end_obj:
    lea     rax, [rbx + 1]
    add     rsp, 16
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret

.fail:
    xor     eax, eax
    add     rsp, 16
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret

; ---- parse_merchant ------------------------------------------------------
; const char *parse_merchant(const char *p, const char *end, Request *r,
;                            const char **id_start, int *id_len);

global parse_merchant
parse_merchant:
    push    rbx
    push    rbp
    push    r12                          ; out
    push    r13                          ; id_start ptr
    push    r14                          ; id_len ptr
    push    r15                          ; got_mcc flag
    sub     rsp, 24                       ; locals (k 8, kl 4+pad, s 8) + alignment.  6 push + 24 → rsp 8 mod16; want 0.  Hmm.
    ; 6 push = -48 mod16 = 8 mod16.  sub 24: 8-24 = -16 ≡ 0 mod16 ✓

    mov     rbx, rdi
    mov     rbp, rsi
    mov     r12, rdx
    mov     r13, rcx
    mov     r14, r8
    xor     r15d, r15d                   ; got_mcc = false

    cmp     rbx, rbp
    jae     .fail
    cmp     byte [rbx], '{'
    jne     .fail
    inc     rbx
    mov     rdi, rbx
    mov     rsi, rbp
    call    skip_ws
    mov     rbx, rax

.loop:
    cmp     rbx, rbp
    jae     .fail
    cmp     byte [rbx], '}'
    je      .end_obj

    mov     rdi, rbx
    mov     rsi, rbp
    lea     rdx, [rsp + 0]
    lea     rcx, [rsp + 8]
    call    read_key
    test    rax, rax
    jz      .fail
    mov     rbx, rax

    TRY_KEY str_id,         2,  .h_id
    TRY_KEY str_mcc,        3,  .h_mcc
    TRY_KEY str_avg_amount, 10, .h_avg

    mov     rdi, rbx
    mov     rsi, rbp
    call    skip_value
    mov     rbx, rax
    jmp     .after

.h_id:
    cmp     rbx, rbp
    jae     .fail
    cmp     byte [rbx], '"'
    jne     .fail
    lea     rax, [rbx + 1]               ; id_start = p+1
    mov     [r13], rax
    mov     [rsp + 16], rax              ; stash id_start for length calc
    lea     rdi, [rbx + 1]
    mov     rsi, rbp
    call    skip_string_body             ; rax = q
    ; id_len = (int)(q - 1 - id_start)
    mov     rcx, rax
    sub     rcx, [rsp + 16]
    dec     rcx
    mov     [r14], ecx                   ; store as i32
    mov     rbx, rax
    jmp     .after

.h_mcc:
    cmp     rbx, rbp
    jae     .fail
    cmp     byte [rbx], '"'
    jne     .fail
    lea     rdi, [rbx + 1]               ; s
    mov     [rsp + 16], rdi
    mov     rsi, rbp
    call    skip_string_body             ; rax = q
    mov     rbx, rax                      ; p = q -- capture BEFORE COPY_MCC_BYTE clobbers al
    ; n = (int)(q - 1 - s)
    mov     rcx, rax
    sub     rcx, [rsp + 16]
    dec     ecx                          ; ecx = n (i32)
    mov     rdi, [rsp + 16]              ; s
    ; Copy first 4 bytes from s, padding with '0' where i >= n.
    COPY_MCC_BYTE 0
    COPY_MCC_BYTE 1
    COPY_MCC_BYTE 2
    COPY_MCC_BYTE 3
    mov     r15d, 1                       ; got_mcc = true
    jmp     .after

.h_avg:
    mov     rdi, rbx
    mov     rsi, rbp
    lea     rdx, [r12 + REQ_MERCHANT_AVG]
    call    parse_number
    mov     rbx, rax
    jmp     .after

.after:
    mov     rdi, rbx
    mov     rsi, rbp
    call    after_value
    mov     rbx, rax
    jmp     .loop

.end_obj:
    test    r15d, r15d
    jz      .fail                         ; mcc required
    lea     rax, [rbx + 1]
    add     rsp, 24
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret

.fail:
    xor     eax, eax
    add     rsp, 24
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret

; ---- parse_terminal ------------------------------------------------------
; const char *parse_terminal(const char *p, const char *end, Request *r);

global parse_terminal
parse_terminal:
    push    rbx
    push    rbp
    push    r12
    sub     rsp, 32

    mov     rbx, rdi
    mov     rbp, rsi
    mov     r12, rdx

    cmp     rbx, rbp
    jae     .fail
    cmp     byte [rbx], '{'
    jne     .fail
    inc     rbx
    mov     rdi, rbx
    mov     rsi, rbp
    call    skip_ws
    mov     rbx, rax

.loop:
    cmp     rbx, rbp
    jae     .fail
    cmp     byte [rbx], '}'
    je      .end_obj

    mov     rdi, rbx
    mov     rsi, rbp
    lea     rdx, [rsp + 0]
    lea     rcx, [rsp + 8]
    call    read_key
    test    rax, rax
    jz      .fail
    mov     rbx, rax

    TRY_KEY str_is_online,    9,  .h_online
    TRY_KEY str_card_present, 12, .h_card
    TRY_KEY str_km_from_home, 12, .h_kmhome

    mov     rdi, rbx
    mov     rsi, rbp
    call    skip_value
    mov     rbx, rax
    jmp     .after

.h_online:
    cmp     byte [rbx], 't'
    sete    al
    mov     [r12 + REQ_IS_ONLINE], al
    mov     rdi, rbx
    mov     rsi, rbp
    call    skip_value
    mov     rbx, rax
    jmp     .after

.h_card:
    cmp     byte [rbx], 't'
    sete    al
    mov     [r12 + REQ_CARD_PRESENT], al
    mov     rdi, rbx
    mov     rsi, rbp
    call    skip_value
    mov     rbx, rax
    jmp     .after

.h_kmhome:
    mov     rdi, rbx
    mov     rsi, rbp
    lea     rdx, [r12 + REQ_KM_HOME]
    call    parse_number
    mov     rbx, rax
    jmp     .after

.after:
    mov     rdi, rbx
    mov     rsi, rbp
    call    after_value
    mov     rbx, rax
    jmp     .loop

.end_obj:
    lea     rax, [rbx + 1]
    add     rsp, 32
    pop     r12
    pop     rbp
    pop     rbx
    ret

.fail:
    xor     eax, eax
    add     rsp, 32
    pop     r12
    pop     rbp
    pop     rbx
    ret

; ---- parse_last_tx -------------------------------------------------------
; const char *parse_last_tx(const char *p, const char *end, Request *r);

global parse_last_tx
parse_last_tx:
    ; null fast-path
    cmp     rdi, rsi
    jae     .obj_path
    cmp     byte [rdi], 'n'
    jne     .obj_path
    mov     byte [rdx + REQ_HAS_LAST_TX], 0
    lea     rax, [rdi + 4]
    ret

.obj_path:
    push    rbx
    push    rbp
    push    r12
    sub     rsp, 32

    mov     rbx, rdi
    mov     rbp, rsi
    mov     r12, rdx

    cmp     rbx, rbp
    jae     .fail
    cmp     byte [rbx], '{'
    jne     .fail
    mov     byte [r12 + REQ_HAS_LAST_TX], 1
    inc     rbx
    mov     rdi, rbx
    mov     rsi, rbp
    call    skip_ws
    mov     rbx, rax

.loop:
    cmp     rbx, rbp
    jae     .fail
    cmp     byte [rbx], '}'
    je      .end_obj

    mov     rdi, rbx
    mov     rsi, rbp
    lea     rdx, [rsp + 0]
    lea     rcx, [rsp + 8]
    call    read_key
    test    rax, rax
    jz      .fail
    mov     rbx, rax

    TRY_KEY str_timestamp,    9,  .h_ts
    TRY_KEY str_km_from_curr, 15, .h_km

    mov     rdi, rbx
    mov     rsi, rbp
    call    skip_value
    mov     rbx, rax
    jmp     .after

.h_ts:
    cmp     rbx, rbp
    jae     .fail
    cmp     byte [rbx], '"'
    jne     .fail
    lea     rdi, [rbx + 1]               ; s
    mov     [rsp + 16], rdi
    mov     rsi, rbp
    call    skip_string_body             ; rax = q
    mov     [rsp + 24], rax
    mov     rcx, rax
    sub     rcx, [rsp + 16]
    dec     rcx                          ; rcx = len
    mov     rdi, [rsp + 16]
    mov     esi, ecx
    call    parse_iso8601
    mov     [r12 + REQ_LAST_TS], rax
    mov     rbx, [rsp + 24]
    jmp     .after

.h_km:
    mov     rdi, rbx
    mov     rsi, rbp
    lea     rdx, [r12 + REQ_KM_LAST]
    call    parse_number
    mov     rbx, rax
    jmp     .after

.after:
    mov     rdi, rbx
    mov     rsi, rbp
    call    after_value
    mov     rbx, rax
    jmp     .loop

.end_obj:
    lea     rax, [rbx + 1]
    add     rsp, 32
    pop     r12
    pop     rbp
    pop     rbx
    ret

.fail:
    xor     eax, eax
    add     rsp, 32
    pop     r12
    pop     rbp
    pop     rbx
    ret

; ---- parse_request -------------------------------------------------------
; int parse_request(const char *body, size_t len, Request *out);
;   rdi = body, rsi = len, rdx = out
;   returns eax = 0 on success, -1 on failure
;
; Frame layout (3 push + sub 320; 0 mod 16 aligned):
;   [rsp +  0..  7]  k
;   [rsp +  8.. 11]  kl
;   [rsp + 16.. 23]  km_start  (init NULL)
;   [rsp + 24.. 31]  km_end    (init NULL)
;   [rsp + 32.. 39]  mid_start (init NULL)
;   [rsp + 40.. 43]  mid_len   (init 0)
;   [rsp + 48..305]  needle[258]
;   [rsp +306..319]  trailing pad

%define PR_K          0
%define PR_KL         8
%define PR_KM_START   16
%define PR_KM_END     24
%define PR_MID_START  32
%define PR_MID_LEN    40
%define PR_NEEDLE     48

global parse_request
parse_request:
    push    rbx                          ; p
    push    rbp                          ; end
    push    r12                          ; out
    sub     rsp, 320

    mov     rbx, rdi                     ; p = body
    mov     rbp, rdi
    add     rbp, rsi                     ; end = body + len
    mov     r12, rdx                     ; out

    ; out->has_last_tx = false; out->known_merchant = false
    mov     byte [r12 + REQ_HAS_LAST_TX], 0
    mov     byte [r12 + REQ_KNOWN_MERCHANT], 0

    ; Zero state slots
    mov     qword [rsp + PR_KM_START],  0
    mov     qword [rsp + PR_KM_END],    0
    mov     qword [rsp + PR_MID_START], 0
    mov     dword [rsp + PR_MID_LEN],   0

    mov     rdi, rbx
    mov     rsi, rbp
    call    skip_ws
    mov     rbx, rax
    cmp     rbx, rbp
    jae     .fail
    cmp     byte [rbx], '{'
    jne     .fail
    inc     rbx
    mov     rdi, rbx
    mov     rsi, rbp
    call    skip_ws
    mov     rbx, rax

.loop:
    cmp     rbx, rbp
    jae     .done_obj                    ; end-of-buffer is acceptable
    cmp     byte [rbx], '}'
    je      .done_obj

    mov     rdi, rbx
    mov     rsi, rbp
    lea     rdx, [rsp + PR_K]
    lea     rcx, [rsp + PR_KL]
    call    read_key
    test    rax, rax
    jz      .fail
    mov     rbx, rax

    TRY_KEY str_transaction, 11, .h_tx
    TRY_KEY str_customer,    8,  .h_cust
    TRY_KEY str_merchant,    8,  .h_merch
    TRY_KEY str_terminal,    8,  .h_term
    TRY_KEY str_last_tx,     16, .h_last

    mov     rdi, rbx
    mov     rsi, rbp
    call    skip_value
    mov     rbx, rax
    jmp     .after

.h_tx:
    mov     rdi, rbx
    mov     rsi, rbp
    mov     rdx, r12
    call    parse_transaction
    test    rax, rax
    jz      .fail
    mov     rbx, rax
    jmp     .after

.h_cust:
    mov     rdi, rbx
    mov     rsi, rbp
    mov     rdx, r12
    lea     rcx, [rsp + PR_KM_START]
    lea     r8,  [rsp + PR_KM_END]
    call    parse_customer
    test    rax, rax
    jz      .fail
    mov     rbx, rax
    jmp     .after

.h_merch:
    mov     rdi, rbx
    mov     rsi, rbp
    mov     rdx, r12
    lea     rcx, [rsp + PR_MID_START]
    lea     r8,  [rsp + PR_MID_LEN]
    call    parse_merchant
    test    rax, rax
    jz      .fail
    mov     rbx, rax
    jmp     .after

.h_term:
    mov     rdi, rbx
    mov     rsi, rbp
    mov     rdx, r12
    call    parse_terminal
    test    rax, rax
    jz      .fail
    mov     rbx, rax
    jmp     .after

.h_last:
    mov     rdi, rbx
    mov     rsi, rbp
    mov     rdx, r12
    call    parse_last_tx
    test    rax, rax
    jz      .fail
    mov     rbx, rax
    jmp     .after

.after:
    mov     rdi, rbx
    mov     rsi, rbp
    call    after_value
    mov     rbx, rax
    jmp     .loop

.done_obj:
    ; Resolve known_merchants membership
    mov     rax, [rsp + PR_KM_START]
    test    rax, rax
    jz      .ret_ok
    mov     rax, [rsp + PR_KM_END]
    test    rax, rax
    jz      .ret_ok
    mov     rax, [rsp + PR_MID_START]
    test    rax, rax
    jz      .ret_ok
    mov     ecx, [rsp + PR_MID_LEN]
    test    ecx, ecx
    jle     .ret_ok
    cmp     ecx, 256
    jge     .ret_ok

    ; Build needle:  '"' + mid_start[0..mid_len-1] + '"'
    mov     byte [rsp + PR_NEEDLE], '"'
    cld
    lea     rdi, [rsp + PR_NEEDLE + 1]
    mov     rsi, [rsp + PR_MID_START]
    movsxd  rcx, dword [rsp + PR_MID_LEN]
    rep     movsb                         ; rdi advances by mid_len
    mov     byte [rdi], '"'

    ; buf_contains(km_start, km_end - km_start, needle, mid_len + 2)
    mov     rdi, [rsp + PR_KM_START]
    mov     rsi, [rsp + PR_KM_END]
    sub     rsi, rdi
    lea     rdx, [rsp + PR_NEEDLE]
    movsxd  rcx, dword [rsp + PR_MID_LEN]
    add     rcx, 2
    call    buf_contains
    mov     [r12 + REQ_KNOWN_MERCHANT], al

.ret_ok:
    xor     eax, eax
    add     rsp, 320
    pop     r12
    pop     rbp
    pop     rbx
    ret

.fail:
    mov     eax, -1
    add     rsp, 320
    pop     r12
    pop     rbp
    pop     rbx
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
