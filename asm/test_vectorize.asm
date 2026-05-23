; Smoke test for vectorize.asm. Runs one Request with hand-computed expected
; Query and compares all 32 bytes. Prints [OK] / [FAIL].

bits 64
default rel

%include "syscalls.inc"
%include "macros.inc"

extern mcc_init
extern vectorize

; ---------------------------------------------------------------------------
section .data
align 8
; Request {
;   amount       = 100.0
;   customer_avg = 50.0
;   merchant_avg = 5000.0
;   km_home      = 100.0
;   km_last      = 5.0
;   ts           = 1700000000  (epoch s, 2023-11-14 22:13:20 UTC, Tuesday)
;   last_ts      = 1699999400  (ts - 600s = 10 min before)
;   installments = 3
;   tx_count_24h = 5
;   mcc          = "5411"       (grocery override -> 1500)
;   is_online       = 1
;   card_present    = 0
;   has_last_tx     = 1
;   known_merchant  = 1
; }
test_request:
    dq 100.0
    dq 50.0
    dq 5000.0
    dq 100.0
    dq 5.0
    dq 1700000000
    dq 1699999400
    dd 3
    dd 5
    db "5411"
    db 1, 0, 1, 1

; ---------------------------------------------------------------------------
section .bss
align 32
test_query: resw 16

; ---------------------------------------------------------------------------
section .rodata
align 2
; Hand-computed expected output for the request above:
;   v[0]  amount/10000          = 0.01     -> 100
;   v[1]  installments/12       = 0.25     -> 2500
;   v[2]  (100/50)/10           = 0.2      -> 2000
;   v[3]  hour=22 /23           ≈ 0.9565   -> 9565
;   v[4]  weekday=1 (Tue) /6    ≈ 0.1667   -> 1667
;   v[5]  minutes=10 /1440      ≈ 0.00694  -> 69
;   v[6]  km_last=5 /1000       = 0.005    -> 50
;   v[7]  km_home=100 /1000     = 0.1      -> 1000
;   v[8]  tx_count_24h=5 /20    = 0.25     -> 2500
;   v[9]  is_online=1                       -> 10000
;   v[10] card_present=0                    -> 0
;   v[11] unknown_merchant (=!known)        -> 0
;   v[12] mcc_risk("5411")                  -> 1500
;   v[13] merchant_avg/10000   = 0.5        -> 5000
;   v[14..15] pad                           -> 0,0
expected_query:
    dw 100, 2500, 2000, 9565, 1667, 69, 50, 1000, 2500, 10000, 0, 0, 1500, 5000, 0, 0

msg_ok:         db "[OK] vectorize", 10
msg_ok_len      equ $ - msg_ok
msg_fail:       db "[FAIL] vectorize", 10
msg_fail_len    equ $ - msg_fail

; ---------------------------------------------------------------------------
section .text
global _start
_start:
    call    mcc_init

    lea     rdi, [test_request]
    lea     rsi, [test_query]
    call    vectorize

    lea     rdi, [test_query]
    lea     rsi, [expected_query]
    mov     ecx, 32                      ; bytes
    cld
    repe    cmpsb
    jne     .fail

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
