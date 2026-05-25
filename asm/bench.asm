; Microbench: measures cycles per request-handling phase without sockets.
;
; Loop = parse_request → vectorize → search.  Each phase is bracketed by
; rdtscp (which serializes the OoO core).  Raw u64 cycle deltas are dumped
; to stdout in 4 consecutive arrays: [parse, vectorize, search, total].
;
; Build:    make -C asm bench
; Run:      asm/build/bench > /tmp/bench.bin
; Analyze:  python3 -c "import numpy as np; ..." (see scripts/bench-analyze.py)

bits 64
default rel

%include "syscalls.inc"
%include "macros.inc"

extern parse_request
extern vectorize
extern search
extern mcc_init
extern index_open

%define NITERS 50000

section .rodata

; Canonical Rinha 2026 POST body.  Backtick string accepts double quotes
; literally without escape soup.
test_body:
    db `{"id":"tx-1","transaction":{"amount":384.88,"installments":3,"requested_at":"2026-03-11T20:23:35Z"},"customer":{"avg_amount":769.76,"tx_count_24h":3,"known_merchants":["MERC-009","MERC-001"]},"merchant":{"id":"MERC-001","mcc":"5912","avg_amount":298.95},"terminal":{"is_online":false,"card_present":true,"km_from_home":13.7},"last_transaction":{"timestamp":"2026-03-11T14:58:35Z","km_from_current":18.8}}`
test_body_len equ $ - test_body

index_path: db "/home/operador/OutroProjetos/rinha2026/rinha-asm/index.bin", 0

section .bss
align 64
ix:        resb 128
req:       resb 80
qvec:      resb 32
align 64
t_parse:   resq NITERS
t_vec:     resq NITERS
t_search:  resq NITERS
t_total:   resq NITERS

section .text

global _start
_start:
    call    mcc_init

    lea     rdi, [ix]
    lea     rsi, [index_path]
    call    index_open
    test    eax, eax
    js      .fail

    ; ---- Warmup: 2000 untimed iterations to settle L1/L2/BPU/TLB ----------
    mov     r15, 2000
.warm:
    lea     rdi, [test_body]
    mov     esi, test_body_len
    lea     rdx, [req]
    call    parse_request
    lea     rdi, [req]
    lea     rsi, [qvec]
    call    vectorize
    lea     rdi, [ix]
    lea     rsi, [qvec]
    call    search
    dec     r15
    jnz     .warm

    ; ---- Measured loop ---------------------------------------------------
    xor     r15, r15                        ; sample index
.loop:
    rdtscp                                  ; t0
    shl     rdx, 32
    or      rax, rdx
    mov     r12, rax

    lea     rdi, [test_body]
    mov     esi, test_body_len
    lea     rdx, [req]
    call    parse_request

    rdtscp                                  ; t1
    shl     rdx, 32
    or      rax, rdx
    mov     r13, rax

    lea     rdi, [req]
    lea     rsi, [qvec]
    call    vectorize

    rdtscp                                  ; t2
    shl     rdx, 32
    or      rax, rdx
    mov     r14, rax

    lea     rdi, [ix]
    lea     rsi, [qvec]
    call    search

    rdtscp                                  ; t3
    shl     rdx, 32
    or      rax, rdx                        ; rax = t3

    ; Store deltas
    mov     rdx, r13
    sub     rdx, r12
    mov     [t_parse + r15*8], rdx          ; parse cycles

    mov     rdx, r14
    sub     rdx, r13
    mov     [t_vec + r15*8], rdx            ; vectorize cycles

    mov     rcx, rax
    sub     rcx, r14
    mov     [t_search + r15*8], rcx         ; search cycles

    sub     rax, r12
    mov     [t_total + r15*8], rax          ; total cycles

    inc     r15
    cmp     r15, NITERS
    jb      .loop

    ; ---- Dump 4 × NITERS × 8B to stdout ---------------------------------
    mov     eax, 1                          ; SYS_write
    mov     edi, 1
    lea     rsi, [t_parse]
    mov     edx, NITERS*8
    syscall

    mov     eax, 1
    mov     edi, 1
    lea     rsi, [t_vec]
    mov     edx, NITERS*8
    syscall

    mov     eax, 1
    mov     edi, 1
    lea     rsi, [t_search]
    mov     edx, NITERS*8
    syscall

    mov     eax, 1
    mov     edi, 1
    lea     rsi, [t_total]
    mov     edx, NITERS*8
    syscall

    mov     eax, 60                         ; SYS_exit
    xor     edi, edi
    syscall

.fail:
    mov     eax, 60
    mov     edi, 1
    syscall

section .note.GNU-stack noalloc noexec nowrite progbits
