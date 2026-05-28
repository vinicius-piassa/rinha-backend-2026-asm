; HTTP framing + request handling for the rinha-2026 API server.
;
; This file delivers:
;   7a -- request-handling layer (pure functions):
;         pre-rendered responses + parse_content_length_line + http_frame +
;         handle_request.
;   7b -- I/O primitives: send_all, bind_control_uds, recv_client_fds.
;   7c -- epoll loop + per-fd state machine + _start entrypoint.  Single
;         thread, level-triggered epoll; per-client buffer in .bss indexed by
;         fd (MAX_FDS slots).  ctrl_fd events fan out SCM_RIGHTS-delivered fds
;         into the epoll set.

bits 64
default rel

%include "syscalls.inc"
%include "macros.inc"

extern parse_request

extern vectorize
extern search
extern mcc_init
extern index_open

%define BUF_SIZE         4096
%define MAX_FDS          1024
%define STATE_SIZE       4104          ; buf(4096) + buf_pos(4) + 4 pad
%define STATE_BUF_POS    4096
%define MAX_EVENTS       128
%define EPOLL_EV_SIZE    12            ; struct epoll_event is __packed
%define EPOLL_EV_FD      4             ; data.fd at offset 4

; IvfIndex struct layout — must stay in sync with build_index.asm's
; write_index_bin and with the on-disk format described in search.asm.
%define IX_FD                0
%define IX_MAP               8
%define IX_MAP_SIZE          16
%define IX_N_CLUSTERS        24
%define IX_N_VECTORS         28
%define IX_CLUSTER_OFFSETS   32
%define IX_BBOX_MIN          40
%define IX_BBOX_MAX          48
%define IX_PAIRS             56
%define IX_LABELS            112
%define IX_BPSOA_MIN         120
%define IX_BPSOA_MAX         128
%define IX_SIZE              144

; Request struct layout (must match parse.asm / vectorize.asm definitions).
; Used by fast_path_classify below; vectorize.asm reads the same offsets.
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

; ===========================================================================
section .rodata

; Pre-rendered HTTP/1.1 responses, one per fraud score bucket.
; Each response is a full message — headers + CRLFCRLF + JSON body — so the
; hot path emits one send().  Body length 35 (true) or 36 (false) baked into
; the Content-Length header verbatim.

%define HDR_TRUE  "HTTP/1.1 200 OK", 13, 10, "Content-Type: application/json", 13, 10, "Content-Length: 35", 13, 10, 13, 10
%define HDR_FALSE "HTTP/1.1 200 OK", 13, 10, "Content-Type: application/json", 13, 10, "Content-Length: 36", 13, 10, 13, 10

fraud_resp_0:
    db HDR_TRUE,  '{"approved":true,"fraud_score":0.0}'
fraud_resp_0_len  equ $ - fraud_resp_0
fraud_resp_1:
    db HDR_TRUE,  '{"approved":true,"fraud_score":0.2}'
fraud_resp_1_len  equ $ - fraud_resp_1
fraud_resp_2:
    db HDR_TRUE,  '{"approved":true,"fraud_score":0.4}'
fraud_resp_2_len  equ $ - fraud_resp_2
fraud_resp_3:
    db HDR_FALSE, '{"approved":false,"fraud_score":0.6}'
fraud_resp_3_len  equ $ - fraud_resp_3
fraud_resp_4:
    db HDR_FALSE, '{"approved":false,"fraud_score":0.8}'
fraud_resp_4_len  equ $ - fraud_resp_4
fraud_resp_5:
    db HDR_FALSE, '{"approved":false,"fraud_score":1.0}'
fraud_resp_5_len  equ $ - fraud_resp_5

align 8
fraud_resp_ptr_table:
    dq fraud_resp_0, fraud_resp_1, fraud_resp_2
    dq fraud_resp_3, fraud_resp_4, fraud_resp_5

align 4
fraud_resp_len_table:
    dd fraud_resp_0_len, fraud_resp_1_len, fraud_resp_2_len
    dd fraud_resp_3_len, fraud_resp_4_len, fraud_resp_5_len

ready_resp:
    db "HTTP/1.1 200 OK", 13, 10, "Content-Length: 0", 13, 10, 13, 10
ready_resp_len equ $ - ready_resp

; Tier-1 fast-path thresholds (corpus-derived conservative cutoffs).
align 8
c_legit_max_amount:  dq 500.0
c_legit_max_ratio:   dq 0.5
c_legit_max_km:      dq 50.0
; fraud min_amount kept at 5000: relaxing to 3000 looked 0-error on
; test-data.json but produced 28 FPs (-438 penalty) on the official bench,
; which uses different payloads.  Tuning thresholds to the local test
; corpus over-fits.  5000 is the conservative-safe value.
c_fraud_min_amount:  dq 5000.0
c_fraud_min_km:      dq 150.0
c_one_d_fp:          dq 1.0

err_resp:
    db "HTTP/1.1 400 Bad Request", 13, 10, "Content-Length: 0", 13, 10, 13, 10
err_resp_len   equ $ - err_resp

; Lowercase reference for case-insensitive Content-Length header detection.
str_cl_lower: db "content-length:"           ; 15 bytes; no NUL

; Default per-partition index paths.  Server loads all 4 at startup; queries
; are routed by partition tag (unknown_merchant × has_last_tx ∈ 0..3).
default_index_p0: db "index_p0.bin", 0
default_index_p1: db "index_p1.bin", 0
default_index_p2: db "index_p2.bin", 0
default_index_p3: db "index_p3.bin", 0
align 8
default_index_paths: dq default_index_p0, default_index_p1, default_index_p2, default_index_p3

usage_msg:          db "usage: asm-server <uds_path>", 10
usage_msg_len  equ $ - usage_msg
err_index_msg:      db "error: failed to open index", 10
err_index_msg_len equ $ - err_index_msg
err_bind_msg:       db "error: bind_control_uds failed", 10
err_bind_msg_len  equ $ - err_bind_msg
dbg_hex:        db "0123456789ABCDEF"

; Static HTTP/POST + canonical JSON body used by warm_handle_request to
; pre-run the full parse + vectorize + search + format pipeline at startup.
; Content-Length is checked at assemble time against the actual body bytes
; so the header never drifts out of sync.
warm_http_req:
    db "POST /fraud-score HTTP/1.1", 13, 10
    db "Host: localhost", 13, 10
    db "Content-Type: application/json", 13, 10
    db "Content-Length: 407", 13, 10
    db 13, 10
warm_body:
    db '{"id":"tx-warm","transaction":{"amount":384.88,"installments":3,"requested_at":"2026-03-11T20:23:35Z"},"customer":{"avg_amount":769.76,"tx_count_24h":3,"known_merchants":["MERC-009","MERC-001"]},"merchant":{"id":"MERC-001","mcc":"5912","avg_amount":298.95},"terminal":{"is_online":false,"card_present":true,"km_from_home":13.7},"last_transaction":{"timestamp":"2026-03-11T14:58:35Z","km_from_current":18.8}}'
warm_http_end:
warm_http_len      equ warm_http_end - warm_http_req
warm_body_off      equ warm_body - warm_http_req
warm_body_len      equ warm_http_end - warm_body

%if warm_body_len != 407
    %error "warm_body_len != 407 — update the Content-Length header"
%endif

; epoll_params struct for EPIOCSPARAMS ioctl (Linux 6.9+).  Hands the kernel
; a budget for NAPI busy-polling inside epoll_wait so we can skip the
; userspace 256× epoll_wait(0) spin entirely.  busy_poll_usecs=50µs gives a
; ~2.5%/sec idle CPU footprint at 900 req/s but slashes per-spin syscall
; framework cost (~57% CPU → ~10-15%) because the spin becomes 1 syscall.
align 8
epoll_busy_params:
    dd 50                                 ; busy_poll_usecs
    dw 8                                  ; busy_poll_budget
    db 1                                  ; prefer_busy_poll
    db 0                                  ; __pad

; ===========================================================================
section .bss

; Read-only after server startup populates them.  Four sub-indices, one per
; (unknown_merchant, has_last_tx) partition tag.  Indexed by tag ∈ 0..3.
global g_indices
alignb 64
g_indices:  resb N_PARTITIONS * IX_SIZE

alignb 16
conn_state: resb MAX_FDS * STATE_SIZE       ; ~4.2 MB; indexed by fd
alignb 16
events_buf: resb MAX_EVENTS * EPOLL_EV_SIZE
ctrl_fd:    resd 1
epoll_fd:   resd 1

; 4K-aliasing guard between conn_state/events_buf and the instrumentation
; counters below.  Bits 0-11 of two recent load/store addresses matching
; → Haswell predicts a false dependency and emits a machine-clear (~15-25
; cycles).  128 B bumps the next block past the aliasing window.
alignb 64
g_alias_pad_a:    resb 128

; Per-phase RDTSC counters (POST path only).  Single-thread accumulators,
; no atomics needed.  dump_stats walks these in order and writes a hex line
; to stderr every 1024 POSTs so `docker logs` can sample steady-state.
;   *_cyc = sum of cycle deltas across all POSTs that exercised that phase
;   *_cnt = number of POSTs that exercised that phase
; total_cnt counts every POST that entered the pipeline regardless of branch.
alignb 64
phase_parse_cyc:    resq 1
phase_parse_cnt:    resq 1
phase_fp_cyc:       resq 1
phase_fp_cnt:       resq 1
phase_vec_cyc:      resq 1
phase_vec_cnt:      resq 1
phase_search_cyc:   resq 1
phase_search_cnt:   resq 1
phase_send_cyc:     resq 1
phase_send_cnt:     resq 1
; Per-syscall counters used to measure keep-alive reuse:
;   recvmsg_cnt = SCM_RIGHTS receives on ctrl_fd (≈ new connections)
;   recvfrom_cnt = client-fd reads (≈ HTTP requests served, includes /ready)
; Ratio recvfrom_cnt/recvmsg_cnt = avg HTTP reqs per connection.
phase_recvmsg_cnt:  resq 1
phase_recvfrom_cnt: resq 1
phase_total_cyc:    resq 1
phase_total_cnt:    resq 1

; ===========================================================================
section .text

; ---- parse_content_length_line --------------------------------------------
; bool parse_content_length_line(const char *p, const char *le, int *out);
;   rdi = p, rsi = le, rdx = out
;   Returns eax = 1 on match (writes *out), 0 otherwise.
;
; Recognizes "Content-Length:" (any case for letters), optional SP/HT, then
; ASCII decimal digits.  Stops at first non-digit or le.

global parse_content_length_line
parse_content_length_line:
    ; ll = le - p
    mov     rax, rsi
    sub     rax, rdi
    cmp     rax, 16
    jl      .no                          ; need at least "Content-Length:" + 1
    ; case-insensitive prefix match: 15 bytes vs str_cl_lower
    lea     r8, [str_cl_lower]
    xor     ecx, ecx                     ; i = 0
.cmp_loop:
    cmp     ecx, 15
    jge     .have_prefix
    movzx   eax, byte [rdi + rcx]
    or      eax, 0x20                    ; lowercase ASCII letters (and a few others, harmless)
    movzx   r9d, byte [r8 + rcx]
    cmp     eax, r9d
    jne     .no
    inc     ecx
    jmp     .cmp_loop

.have_prefix:
    xor     ecx, ecx                     ; n = 0 (must precede the no-digits path)
    lea     r9, [rdi + 15]               ; q
    ; Skip optional SP / HT
.skip_ws:
    cmp     r9, rsi
    jae     .digits_done
    movzx   eax, byte [r9]
    cmp     al, ' '
    je      .skip_ws_inc
    cmp     al, 9
    jne     .digits
.skip_ws_inc:
    inc     r9
    jmp     .skip_ws

.digits:
.digit_loop:
    cmp     r9, rsi
    jae     .digits_done
    movzx   eax, byte [r9]
    sub     eax, '0'
    cmp     eax, 9
    ja      .digits_done                 ; not 0..9
    lea     ecx, [ecx + ecx*4]           ; n *= 5
    lea     ecx, [eax + ecx*2]           ; n = 10*n + digit
    inc     r9
    cmp     ecx, BUF_SIZE
    jbe     .digit_loop
    ; Saturate above BUF_SIZE to keep n*hsz arithmetic safe in http_frame
    ; and force the request into the incomplete/oversize bucket.
    mov     ecx, BUF_SIZE + 1
.eat_oversized:
    cmp     r9, rsi
    jae     .digits_done
    movzx   eax, byte [r9]
    sub     eax, '0'
    cmp     eax, 9
    ja      .digits_done
    inc     r9
    jmp     .eat_oversized

.digits_done:
    mov     [rdx], ecx                   ; *out = n
    mov     eax, 1
    ret

.no:
    xor     eax, eax
    ret

; ---- http_frame -----------------------------------------------------------
; int http_frame(const char *buf, int len, int *body_off, int *body_len);
;   rdi = buf, esi = len, rdx = body_off out, rcx = body_len out
;   Returns eax = total bytes of one full HTTP request (header + body) if a
;   complete request is in buf, 0 if more bytes are needed.
;
; CRLFCRLF terminator search is linear; Content-Length lookup tries the last
; header line first (k6 sends C-L last), then falls back to a scan.

global http_frame
http_frame:
    push    rbx                          ; buf
    push    rbp                          ; body_off out
    push    r12                          ; body_len out
    push    r13                          ; len (signed int as 64-bit)
    push    r14                          ; he ptr
    push    r15                          ; cl scratch (int)
    sub     rsp, 24                      ; locals: cl(4)+got(4)+pad(16); 6 push + 24 → mod16=0

    mov     rbx, rdi                     ; buf
    mov     rbp, rdx
    mov     r12, rcx
    movsxd  r13, esi                     ; len as i64

    ; --- find CRLFCRLF -----------------------------------------------------
    ; AVX2: scan 32-byte chunks with 4 shifted unaligned loads against
    ; broadcast(CR)/broadcast(LF), ANDed → mask of CRLFCRLF starts.  Each
    ; iter advances by 32, but needs rcx+34 < len for the +3 load — last
    ; <35 bytes drained byte-by-byte.
    mov     eax, 0x0D
    vmovd   xmm14, eax
    vpbroadcastb ymm14, xmm14            ; ymm14 = CR broadcast
    mov     eax, 0x0A
    vmovd   xmm13, eax
    vpbroadcastb ymm13, xmm13            ; ymm13 = LF broadcast

    xor     ecx, ecx                     ; i = 0
.crlf_simd:
    ; Need rcx + 35 ≤ len for the +3 unaligned ymm read to stay in-bounds.
    mov     rax, rcx
    add     rax, 35
    cmp     rax, r13
    jg      .crlf_tail

    vmovdqu  ymm0, [rbx + rcx]
    vmovdqu  ymm1, [rbx + rcx + 1]
    vmovdqu  ymm2, [rbx + rcx + 2]
    vmovdqu  ymm3, [rbx + rcx + 3]
    vpcmpeqb ymm0, ymm0, ymm14           ; CR at offset 0
    vpcmpeqb ymm1, ymm1, ymm13           ; LF at offset 1
    vpcmpeqb ymm2, ymm2, ymm14           ; CR at offset 2
    vpcmpeqb ymm3, ymm3, ymm13           ; LF at offset 3
    vpand    ymm0, ymm0, ymm1
    vpand    ymm2, ymm2, ymm3
    vpand    ymm0, ymm0, ymm2
    vpmovmskb eax, ymm0
    test     eax, eax
    jz       .crlf_advance
    tzcnt    edx, eax
    add      rcx, rdx                     ; i = chunk_base + first match
    lea      r14, [rbx + rcx]
    jmp      .have_he
.crlf_advance:
    add      rcx, 32
    jmp      .crlf_simd

.crlf_tail:
    ; Byte-by-byte for the last <35 bytes.
    mov     rax, rcx
    add     rax, 3
    cmp     rax, r13
    jge     .no_crlf
    cmp     byte [rbx + rcx], 13
    jne     .crlf_tail_next
    cmp     byte [rbx + rcx + 1], 10
    jne     .crlf_tail_next
    cmp     byte [rbx + rcx + 2], 13
    jne     .crlf_tail_next
    cmp     byte [rbx + rcx + 3], 10
    jne     .crlf_tail_next
    lea     r14, [rbx + rcx]
    jmp     .have_he
.crlf_tail_next:
    inc     rcx
    jmp     .crlf_tail

.no_crlf:
    xor     eax, eax                     ; return 0
    jmp     .ret

.have_he:
    ; cl = 0; got = false
    mov     dword [rsp + 0], 0           ; cl
    mov     dword [rsp + 4], 0           ; got (0/1)

    ; --- try last header line first ---------------------------------------
    ; last = he; while (last > buf+1 && !(last[-2]==CR && last[-1]==LF)) last--;
    mov     rax, r14                     ; last = he
.last_scan:
    lea     r9, [rbx + 1]                ; buf + 1
    cmp     rax, r9
    jbe     .have_last
    cmp     byte [rax - 2], 13
    jne     .last_dec
    cmp     byte [rax - 1], 10
    je      .have_last
.last_dec:
    dec     rax
    jmp     .last_scan

.have_last:
    mov     rdi, rax                     ; p
    mov     rsi, r14                     ; le = he
    lea     rdx, [rsp + 0]               ; &cl
    call    parse_content_length_line
    test    eax, eax
    jz      .scan_headers
    mov     dword [rsp + 4], 1           ; got = true
    jmp     .compute_total

    ; --- fallback: scan all header lines for Content-Length ---------------
.scan_headers:
    mov     r8, rbx                      ; p = buf
.scan_loop:
    ; if (p > he) break; in C: while (p <= he)
    cmp     r8, r14
    ja      .compute_total
    ; le = memchr(p, '\r', he + 1 - p)
    mov     r9, r14
    sub     r9, r8
    inc     r9                           ; count = he + 1 - p
    mov     rdi, r8
.memchr:
    test    r9, r9
    jz      .compute_total               ; not found ⇒ stop
    cmp     byte [rdi], 13
    je      .le_found
    inc     rdi
    dec     r9
    jmp     .memchr
.le_found:
    ; rdi = le; call parse_content_length_line(p=r8, le=rdi, &cl)
    mov     rsi, rdi                     ; le
    mov     rdi, r8                      ; p
    lea     rdx, [rsp + 0]
    call    parse_content_length_line
    test    eax, eax
    jz      .scan_next
    mov     dword [rsp + 4], 1
    jmp     .compute_total
.scan_next:
    ; p = le + 2  (skip CRLF)
    add     rsi, 2                       ; rsi was le
    mov     r8, rsi
    jmp     .scan_loop

.compute_total:
    ; hsz = (int)(he - buf) + 4
    mov     rax, r14
    sub     rax, rbx
    add     eax, 4                       ; hsz (i32 OK)
    ; total = hsz + (got ? cl : 0)
    mov     ecx, dword [rsp + 4]
    test    ecx, ecx
    jz      .no_body
    add     eax, dword [rsp + 0]
.no_body:
    ; if (len < total) return 0
    cmp     r13d, eax
    jl      .incomplete

    ; *body_off = hsz; *body_len = got ? cl : 0
    mov     ecx, eax                     ; total (we will overwrite below; save)
    mov     edx, dword [rsp + 4]         ; got
    mov     r9d, 0
    test    edx, edx
    cmovnz  r9d, dword [rsp + 0]         ; cl if got
    mov     edx, r9d                     ; body_len
    mov     [r12], edx
    ; body_off = hsz = total - body_len
    mov     r9d, ecx
    sub     r9d, edx
    mov     [rbp], r9d
    mov     eax, ecx                     ; return total

.ret:
    ; vzeroupper before unwinding so caller (and any syscall it makes before
    ; the next AVX use, e.g. partial-recv re-entry into recvfrom) sees AVX
    ; state "init" — kernel XSAVE/XRSTOR on syscall transition skips the
    ; AVX block (the ymm14/ymm13 broadcasts above leave the upper halves
    ; dirty otherwise).
    vzeroupper
    add     rsp, 24
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret

.incomplete:
    xor     eax, eax
    jmp     .ret

; ---- fast_path_classify --------------------------------------------------
; int fast_path_classify(const Request *r);   rdi = Request*
;   Returns: 0 (obvious legit), 5 (obvious fraud), or -1 (k-NN required).
;
; Conservative deterministic tier-1 rules: ALL conditions must hold for a
; fast-path verdict.  Mirrors the obvious_legit / obvious_fraud rules from
; the two leading entries.  Detection-safe: rules only fire on extreme
; payloads (small + safe-mcc + low-risk customer for legit; high amount +
; risky-mcc + unknown-merchant for fraud).
;
; All comparisons follow `> threshold → fail` semantics (strict), so border
; values (amount == 500.0 exact) stay in fast-path.  MCC matched as a 4-byte
; ASCII u32 (the bytes at REQ_MCC are guaranteed to be '0'..'9' digits).

fast_path_classify:
    ; ---- obvious_legit ----------------------------------------------------
    cmp     byte [rdi + REQ_KNOWN_MERCHANT], 1
    jne     .check_fraud
    cmp     dword [rdi + REQ_INSTALLMENTS], 3
    jg      .check_fraud
    cmp     dword [rdi + REQ_TX_COUNT_24H], 5
    jg      .check_fraud
    movsd   xmm0, [rdi + REQ_AMOUNT]
    ucomisd xmm0, [c_legit_max_amount]
    ja      .check_fraud                 ; amount > 500 → not legit
    ; ratio: amount / max(customer_avg, 1.0) > 0.5 → not legit
    movsd   xmm1, [rdi + REQ_CUSTOMER_AVG]
    movsd   xmm2, [c_one_d_fp]
    maxsd   xmm1, xmm2                   ; safe_avg = max(avg, 1.0)
    divsd   xmm0, xmm1
    ucomisd xmm0, [c_legit_max_ratio]
    ja      .check_fraud                 ; ratio > 0.5 → not legit
    movsd   xmm0, [rdi + REQ_KM_HOME]
    ucomisd xmm0, [c_legit_max_km]
    ja      .check_fraud                 ; km > 50 → not legit
    ; safe_mcc ∈ {5411, 5812, 5912, 5311}
    mov     eax, [rdi + REQ_MCC]
    cmp     eax, 0x31313435              ; '5','4','1','1' little-endian
    je      .legit
    cmp     eax, 0x32313835              ; '5','8','1','2'
    je      .legit
    cmp     eax, 0x32313935              ; '5','9','1','2'
    je      .legit
    cmp     eax, 0x31313335              ; '5','3','1','1'
    je      .legit
    ; fall through — mcc not safe

.check_fraud:
    ; ---- obvious_fraud ---------------------------------------------------
    cmp     byte [rdi + REQ_KNOWN_MERCHANT], 0
    jne     .ambiguous                   ; known merchant → not fraud
    cmp     dword [rdi + REQ_INSTALLMENTS], 5
    jl      .ambiguous
    cmp     dword [rdi + REQ_TX_COUNT_24H], 6
    jl      .ambiguous
    movsd   xmm0, [rdi + REQ_AMOUNT]
    ucomisd xmm0, [c_fraud_min_amount]
    jb      .ambiguous                   ; amount < 5000 → not fraud
    movsd   xmm0, [rdi + REQ_KM_HOME]
    ucomisd xmm0, [c_fraud_min_km]
    jb      .ambiguous                   ; km < 150 → not fraud
    ; risky_mcc ∈ {7995, 7801, 7802}
    mov     eax, [rdi + REQ_MCC]
    cmp     eax, 0x35393937              ; '7','9','9','5'
    je      .fraud
    cmp     eax, 0x31303837              ; '7','8','0','1'
    je      .fraud
    cmp     eax, 0x32303837              ; '7','8','0','2'
    je      .fraud

.ambiguous:
    mov     eax, -1
    ret
.legit:
    xor     eax, eax
    ret
.fraud:
    mov     eax, 5
    ret

; ---- handle_request -------------------------------------------------------
; const char *handle_request(const char *buf, int total, int body_off,
;                            int body_len, int *out_len);
;   rdi = buf, esi = total, edx = body_off, ecx = body_len, r8 = out_len
;   Returns rax = pointer to the response bytes; writes its length via *out_len.
;
; Locals (sub rsp, 120; 4 push → 8 mod 16, sub 120 mod 16=8 → 0 ✓):
;   [rsp +   0.. 71]  Request req
;   [rsp +  72..103]  Query q
;   [rsp + 104..119]  pad/scratch

global handle_request
handle_request:
    push    rbx                          ; buf
    push    rbp                          ; total
    push    r12                          ; out_len
    push    r13                          ; body_off (for the POST branch)
    sub     rsp, 120

    mov     rbx, rdi
    movsxd  rbp, esi
    mov     r12, r8
    movsxd  r13, edx                     ; body_off

    ; Instrumentation slots in scratch zone:
    ;   [rsp + 104] = req_start_tsc
    ;   [rsp + 112] = phase_start_tsc
    ; Saved here before any phase call so they survive callee clobbers.

    ; --- POST? (total >= 5 && buf[0..3] == "POST" && buf[4] == ' ') ------
    cmp     rbp, 5
    jl      .check_get
    cmp     dword [rbx], 0x54534F50      ; bytes 'P','O','S','T' little-endian
    jne     .check_get
    cmp     byte [rbx + 4], ' '
    jne     .err

    ; --- POST path ---------------------------------------------------------
    ; Zero Request (72 B).
    pxor    xmm0, xmm0
    movdqu  [rsp + 0],  xmm0
    movdqu  [rsp + 16], xmm0
    movdqu  [rsp + 32], xmm0
    movdqu  [rsp + 48], xmm0
    mov     qword [rsp + 64], 0          ; 8 bytes covers mcc+is_online..known_merchant (8 bytes)

%ifdef INSTRUMENT
    ; Instrumentation: latch req_start_tsc and phase_start_tsc.
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     [rsp + 104], rax
    mov     [rsp + 112], rax
%endif

    ; parse_request(buf + body_off, body_len, &req)
    ; (rcx still holds body_len: only pxor/movdqu/mov-imm above, none clobber)
    lea     rdi, [rbx + r13]             ; buf + body_off
    movsxd  rsi, ecx                     ; body_len
    lea     rdx, [rsp + 0]               ; &req
    call    parse_request
    test    eax, eax
    jnz     .post_err                    ; parse_request != 0 → 400

%ifdef INSTRUMENT
    ; Instrumentation: parse_request delta.
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     rcx, rax
    sub     rax, [rsp + 112]
    add     [rel phase_parse_cyc], rax
    inc     qword [rel phase_parse_cnt]
    mov     [rsp + 112], rcx
%endif

    ; Tier-1 fast-path: deterministic obvious_legit / obvious_fraud rules.
    ; Sub-200 ns and bypasses both vectorize + scan_cluster on the few
    ; queries that meet ALL conditions in either bucket.  Returns -1 when
    ; the verdict is ambiguous — that case falls through to the full k-NN.
    lea     rdi, [rsp + 0]
    call    fast_path_classify

%ifdef INSTRUMENT
    ; Instrumentation: fast_path_classify delta — preserve eax verdict.
    mov     r9d, eax
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     rcx, rax
    sub     rax, [rsp + 112]
    add     [rel phase_fp_cyc], rax
    inc     qword [rel phase_fp_cnt]
    mov     [rsp + 112], rcx
    mov     eax, r9d                     ; restore verdict
%endif

    test    eax, eax
    js      .knn_path                    ; eax == -1 → ambiguous
    jmp     .fraud_ok                    ; eax ∈ {0, 5} → done

.knn_path:
    ; vectorize(&req, &q)
    lea     rdi, [rsp + 0]
    lea     rsi, [rsp + 72]
    call    vectorize

%ifdef INSTRUMENT
    ; Instrumentation: vectorize delta.
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     rcx, rax
    sub     rax, [rsp + 112]
    add     [rel phase_vec_cyc], rax
    inc     qword [rel phase_vec_cnt]
    mov     [rsp + 112], rcx
%endif

    ; Derive partition tag = (unknown << 1) | has_last from Request.  Then
    ; route the search to the matching sub-index.  unknown = 1 - known.
    movzx   eax, byte [rsp + REQ_KNOWN_MERCHANT]   ; 1 if known, 0 if unknown
    xor     eax, 1                                  ; flip → unknown bit
    shl     eax, 1
    movzx   ecx, byte [rsp + REQ_HAS_LAST_TX]
    or      eax, ecx                                ; eax = tag ∈ 0..3
    imul    eax, eax, IX_SIZE
    lea     rdi, [g_indices]
    add     rdi, rax                                ; rdi = &g_indices[tag]
    lea     rsi, [rsp + 72]
    call    search

%ifdef INSTRUMENT
    ; Instrumentation: search delta — preserve eax (fraud_count).
    mov     r9d, eax
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     rcx, rax
    sub     rax, [rsp + 112]
    add     [rel phase_search_cyc], rax
    inc     qword [rel phase_search_cnt]
    mov     [rsp + 112], rcx
    movzx   eax, r9b                     ; restore fraud_count, zero-ext
%else
    movzx   eax, al                      ; zero-ext fraud_count (search ret ∈ 0..5)
%endif

    cmp     eax, 5
    jbe     .fraud_ok
    mov     eax, 5
.fraud_ok:
    ; *out_len = fraud_resp_len[fraud]; return fraud_resp[fraud]
    lea     rcx, [fraud_resp_len_table]
    mov     ecx, [rcx + rax*4]
    mov     [r12], ecx
    lea     rdx, [fraud_resp_ptr_table]
    mov     rax, [rdx + rax*8]

%ifdef INSTRUMENT
    ; Instrumentation: POST total = t_now - req_start; dump every 1024.
    mov     r8, rax                      ; preserve response ptr
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    sub     rax, [rsp + 104]
    add     [rel phase_total_cyc], rax
    inc     qword [rel phase_total_cnt]
    mov     rcx, [rel phase_total_cnt]
    test    ecx, 1023
    jnz     .no_stats_dump
    ; Stash response ptr in the (already-consumed) req_start slot so we
    ; survive dump_stats without pushing (which would misalign rsp).
    mov     [rsp + 104], r8
    call    dump_stats
    mov     r8,  [rsp + 104]
.no_stats_dump:
    mov     rax, r8                      ; restore response ptr
%endif
    jmp     .ret

.post_err:
    lea     rax, [err_resp]
    mov     dword [r12], err_resp_len
    jmp     .ret

.check_get:
    cmp     rbp, 5
    jl      .err
    cmp     word [rbx], 0x4547           ; "GE"
    jne     .err
    cmp     byte [rbx + 2], 'T'
    jne     .err
    cmp     byte [rbx + 3], ' '
    jne     .err

    ; (Previously: on the first GET /ready we re-ran warm_handle_request
    ; here to refresh BPU/L1i.  That blocks the single-threaded event loop
    ; for 5–50ms; under the epoll port it creates cascading backpressure
    ; — LB.send_fd stalls on a full ctrl UDS queue, accept_loop stops
    ; running, new TCP connections never get serviced.  The startup pass
    ; in _start already primes the predictor; the marginal benefit of the
    ; re-warm doesn't justify the deadlock window.)
    lea     rax, [ready_resp]
    mov     dword [r12], ready_resp_len
    jmp     .ret

.err:
    lea     rax, [err_resp]
    mov     dword [r12], err_resp_len

.ret:
    add     rsp, 120
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret

; ---- send_all -------------------------------------------------------------
; int send_all(int fd, const char *p, int n);
;   rdi = fd, rsi = p, edx = n
;   Returns 0 on full send, -1 on error.  Retries on EINTR; treats short
;   writes by advancing the offset.  Uses sendto() with NULL dest, which is
;   the kernel ABI for send() (no separate `send` syscall on x86_64).

global send_all
send_all:
    push    rbx                          ; fd
    push    rbp                          ; p (base)
    push    r12                          ; n (remaining bytes signed)
    push    r13                          ; off (sent so far)
    push    r14                          ; t_start for per-sendto RDTSC timing
                                         ; 5 pushes → rsp 0 mod 16 ✓

    mov     ebx, edi
    mov     rbp, rsi
    movsxd  r12, edx
    xor     r13d, r13d

.loop:
    cmp     r13, r12
    jge     .done

%ifdef INSTRUMENT
    ; --- RDTSC start (preserves nothing; we save into r14) ---
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     r14, rax
%endif

    mov     edi, ebx                     ; fd
    lea     rsi, [rbp + r13]             ; p + off
    mov     rdx, r12
    sub     rdx, r13                     ; n - off
    mov     r10d, MSG_NOSIGNAL
    xor     r8d, r8d                     ; addr = NULL
    xor     r9d, r9d                     ; addrlen = 0
    syscall0 SYS_sendto

%ifdef INSTRUMENT
    ; --- RDTSC end + accumulate (preserve sendto retval in r9) ---
    mov     r9, rax                      ; r9 preserved across SYSCALL per ABI
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    sub     rax, r14                     ; delta cycles
    add     [rel phase_send_cyc], rax
    inc     qword [rel phase_send_cnt]
    mov     rax, r9                      ; restore sendto retval
%endif

    test    rax, rax
    js      .check_eintr
    add     r13, rax
    jmp     .loop

.check_eintr:
    cmp     rax, -EINTR
    jne     .err
    jmp     .loop

.done:
    xor     eax, eax
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret

.err:
    mov     eax, -1
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret

; ---- bind_control_uds -----------------------------------------------------
; int bind_control_uds(const char *path);
;   rdi = path  (NUL-terminated, ≤107 bytes)
;   Returns the ctrl fd (≥0) after the LB has connected, or -1 on error.
;
; Sequence:
;   unlink(path)                           [best-effort cleanup of stale socket]
;   fd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0)
;   build sockaddr_un { AF_UNIX, path } on stack
;   bind(fd, &addr, 110)                   [sizeof sockaddr_un on Linux]
;   chmod(path, 0666)                       [LB runs as a different uid usually]
;   listen(fd, 8)
;   ctrl = accept4(fd, NULL, NULL, SOCK_CLOEXEC)   [blocks]
;   close(fd)
;   return ctrl
;
; Stack frame: 2 pushes + sub 120  →  rsp 0 mod 16 ✓
;   [rsp + 0..109]  sockaddr_un (sun_family + sun_path[108])
;   [rsp + 110..119] pad

global bind_control_uds
bind_control_uds:
    push    rbx                          ; listening fd
    push    r12                          ; path ptr
    sub     rsp, 120

    mov     r12, rdi                     ; path

    ; unlink(path) — ignore failure
    mov     rdi, r12
    syscall0 SYS_unlink

    ; fd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0)
    mov     edi, AF_UNIX
    mov     esi, SOCK_STREAM | SOCK_CLOEXEC
    xor     edx, edx
    syscall0 SYS_socket
    test    rax, rax
    js      .fail
    mov     rbx, rax                     ; fd

    ; Zero sockaddr_un (112 bytes covered)
    pxor    xmm0, xmm0
    movdqu  [rsp + 0],   xmm0
    movdqu  [rsp + 16],  xmm0
    movdqu  [rsp + 32],  xmm0
    movdqu  [rsp + 48],  xmm0
    movdqu  [rsp + 64],  xmm0
    movdqu  [rsp + 80],  xmm0
    movdqu  [rsp + 96],  xmm0

    ; sun_family = AF_UNIX  (offset 0, u16)
    mov     word [rsp + 0], AF_UNIX

    ; Copy path → sun_path (offset 2), bounded at 107 bytes
    lea     rdi, [rsp + 2]
    mov     rsi, r12
    mov     ecx, 107
.cp_loop:
    test    ecx, ecx
    jz      .cp_done
    movzx   eax, byte [rsi]
    test    al, al
    jz      .cp_done
    mov     [rdi], al
    inc     rdi
    inc     rsi
    dec     ecx
    jmp     .cp_loop
.cp_done:

    ; bind(fd, &addr, 110)
    mov     edi, ebx
    mov     rsi, rsp
    mov     edx, 110
    syscall0 SYS_bind
    test    rax, rax
    js      .fail_close

    ; chmod(path, 0o666 = 438) — best-effort
    mov     rdi, r12
    mov     esi, 438
    syscall0 SYS_chmod

    ; listen(fd, 8)
    mov     edi, ebx
    mov     esi, 8
    syscall0 SYS_listen
    test    rax, rax
    js      .fail_close

    ; ctrl = accept4(fd, NULL, NULL, SOCK_CLOEXEC) — blocks
.accept:
    mov     edi, ebx
    xor     esi, esi
    xor     edx, edx
    mov     r10d, SOCK_CLOEXEC
    syscall0 SYS_accept4
    cmp     rax, -EINTR
    je      .accept
    test    rax, rax
    js      .fail_close

    ; Close listening fd, return ctrl fd (still in rax-region; cache it)
    mov     r12, rax                     ; ctrl
    mov     edi, ebx
    syscall0 SYS_close
    mov     rax, r12

    add     rsp, 120
    pop     r12
    pop     rbx
    ret

.fail_close:
    mov     edi, ebx
    syscall0 SYS_close
.fail:
    mov     eax, -1
    add     rsp, 120
    pop     r12
    pop     rbx
    ret

; ---- recv_client_fds ------------------------------------------------------
; int recv_client_fds(int ctrl_fd, int *out_fds, int max_fds, int *out_nfds);
;   rdi = ctrl_fd, rsi = out_fds, edx = max_fds, rcx = out_nfds
;   Returns:
;     -1 on syscall error
;      0 on EOF (recvmsg returned 0)
;      1 on success; *out_nfds gets the number of fds copied.
;
; Performs a single recvmsg() and parses every SCM_RIGHTS cmsg block in the
; returned control buffer.  Up to 8 fds total (CMSG_SPACE(8*sizeof(int)) = 48).
;
; Stack frame: 3 pushes + sub 192  →  rsp 0 mod 16 ✓
;   [rsp +   0.. 63]  iobuf       (64 B)
;   [rsp +  64..111]  cmsg_buf    (48 B)
;   [rsp + 112..127]  iovec       (16 B)
;   [rsp + 128..183]  msghdr      (56 B)
;   [rsp + 184..191]  pad

global recv_client_fds
recv_client_fds:
    push    rbx                          ; ctrl_fd
    push    r12                          ; out_fds
    push    r13                          ; max_fds | out_nfds
    sub     rsp, 192

    mov     ebx, edi
    mov     r12, rsi
    mov     r13, rcx                     ; out_nfds ptr (rcx free)
    movsxd  rax, edx                     ; max_fds → 64-bit (preserved)
    mov     [rsp + 184], eax             ; stash max_fds at [rsp+184]

    ; iovec at [rsp+112]: { iov_base = rsp, iov_len = 64 }
    lea     rax, [rsp + 0]
    mov     [rsp + 112], rax
    mov     qword [rsp + 120], 64

    ; msghdr at [rsp+128]: zero, then set fields
    pxor    xmm0, xmm0
    movdqu  [rsp + 128], xmm0
    movdqu  [rsp + 144], xmm0
    movdqu  [rsp + 160], xmm0
    movdqu  [rsp + 176], xmm0            ; reaches 192 — slightly past our msghdr (56B end at 184), fine
    lea     rax, [rsp + 112]             ; iovec ptr
    mov     [rsp + 144], rax             ; msg_iov
    mov     qword [rsp + 152], 1         ; msg_iovlen
    lea     rax, [rsp + 64]              ; cmsg_buf
    mov     [rsp + 160], rax             ; msg_control
    mov     qword [rsp + 168], 48        ; msg_controllen

    ; Restore max_fds stash (overwritten by msghdr zeroing)
    movsxd  rax, edx
    mov     [rsp + 184], eax

.retry:
    ; recvmsg(ctrl_fd, &msg, MSG_CMSG_CLOEXEC | MSG_DONTWAIT)
    ; — keep passed fds O_CLOEXEC; non-blocking so EAGAIN cleanly signals
    ;   "drained" to the epoll edge-triggered handler.
    mov     edi, ebx
    lea     rsi, [rsp + 128]
    mov     edx, MSG_CMSG_CLOEXEC | MSG_DONTWAIT
    syscall0 SYS_recvmsg
    cmp     rax, -EINTR
    je      .retry
    test    rax, rax
    js      .err
    jz      .eof
%ifdef INSTRUMENT
    inc     qword [rel phase_recvmsg_cnt]
%endif

    ; Walk cmsg buffer: ptr = rsp+64, end = ptr + msg_controllen
    mov     r8, [rsp + 168]              ; actual msg_controllen (may shrink)
    lea     rcx, [rsp + 64]              ; cmsg cursor
    lea     r9,  [rcx + r8]              ; cmsg end
    xor     r10d, r10d                   ; nfds_count = 0

.walk:
    ; Need at least one full cmsghdr (16 B) remaining.
    lea     rax, [rcx + 16]
    cmp     rax, r9
    ja      .walk_done

    mov     rdi, [rcx + 0]               ; cmsg_len
    cmp     rdi, 16
    jb      .walk_done                   ; malformed (under cmsghdr size)
    mov     rax, r9
    sub     rax, rcx                     ; remaining bytes in buffer
    cmp     rdi, rax
    ja      .walk_done                   ; cmsg_len overruns buffer → bail
    mov     eax, [rcx + 8]               ; cmsg_level
    cmp     eax, SOL_SOCKET
    jne     .walk_next
    mov     eax, [rcx + 12]              ; cmsg_type
    cmp     eax, SCM_RIGHTS
    jne     .walk_next

    ; n_in_this_block = (cmsg_len - 16) / 4
    mov     r11, rdi
    sub     r11, 16
    shr     r11, 2                       ; n fds in this cmsg

    ; Copy fds, clamped to max_fds total
    movsxd  rdx, dword [rsp + 184]       ; max_fds
    mov     rsi, rdx
    sub     rsi, r10                     ; remaining = max - count
    cmp     r11, rsi
    cmovg   r11, rsi                     ; clamp
    test    r11, r11
    jle     .walk_next                   ; nothing to copy

    ; rdi <- src: cmsg data starts at cmsg + 16
    lea     rsi, [rcx + 16]
    ; rdi <- dst: out_fds + nfds_count
    lea     rdi, [r12 + r10*4]
    mov     rdx, r11                     ; count of i32s

.copy:
    test    rdx, rdx
    jz      .copy_done
    mov     eax, [rsi]
    mov     [rdi], eax
    add     rsi, 4
    add     rdi, 4
    dec     rdx
    jmp     .copy
.copy_done:
    add     r10, r11                     ; nfds_count += n

.walk_next:
    ; Advance cmsg: ptr += ALIGN_UP(cmsg_len, 8)
    mov     rax, [rcx + 0]               ; cmsg_len (signed safe)
    add     rax, 7
    and     rax, -8
    add     rcx, rax
    jmp     .walk

.walk_done:
    ; *out_nfds = nfds_count
    mov     [r13], r10d
    mov     eax, 1
    add     rsp, 192
    pop     r13
    pop     r12
    pop     rbx
    ret

.eof:
    mov     dword [r13], 0
    xor     eax, eax
    add     rsp, 192
    pop     r13
    pop     r12
    pop     rbx
    ret

.err:
    mov     dword [r13], 0
    mov     eax, -1
    add     rsp, 192
    pop     r13
    pop     r12
    pop     rbx
    ret

; ===========================================================================
; epoll event loop (single-thread, edge-triggered)
; ===========================================================================
;
; ctrl_fd  — Unix stream socket from LB carrying SCM_RIGHTS batches of
;            accepted client TCP fds.  Registered EPOLLIN | EPOLLET.
; client   — short-lived TCP fds attached on the fly.  Registered
;            EPOLLIN | EPOLLET | EPOLLRDHUP so peer half-close fires
;            without depending on a subsequent recv == 0.
;
; Each event drains its source until EAGAIN before returning, as
; required by edge-triggered semantics — otherwise the kernel won't
; re-arm until the next state-change edge.

; ---- handle_ctrl_event ----------------------------------------------------
; Processes ONE batch of fds from the LB → API control socket (recv_client_fds
; does a single recvmsg).  No drain loop — under level-triggered epoll plus
; the server_loop_epoll busy-poll spin, any fd still queued in the kernel
; buffer is observed on the very next epoll_wait(0) (~200 ns later) instead
; of via an in-handler EAGAIN drain.  Saves one wasted recvmsg per ctrl event.

handle_ctrl_event:
    push    rbx                          ; ctrl_fd
    push    r12                          ; nfds
    push    r13                          ; iter i
    sub     rsp, 288                     ; fds[64] (256B) + scratch (32B)
                                         ;   [+4  ] epoll_event { events(4), fd(4) }
                                         ;   [+16 ] nfds (4)
                                         ;   [+32 ] fds[64] (256)

    mov     ebx, edi

    mov     edi, ebx
    lea     rsi, [rsp + 32]              ; out_fds
    mov     edx, 64                       ; max_fds
    lea     rcx, [rsp + 16]              ; &nfds
    call    recv_client_fds
    test    eax, eax
    js      .done                         ; -1 → recvmsg err (EAGAIN included)
    jz      .done                         ; 0  → EOF

    mov     r12d, [rsp + 16]
    test    r12d, r12d
    jz      .done                         ; no fds in this batch — return

    xor     r13d, r13d
.add_loop:
    cmp     r13d, r12d
    jge     .done

    mov     eax, [rsp + 32 + r13*4]      ; new client fd

    ; Bounds check: conn_state is fd-indexed with MAX_FDS slots.  Under
    ; normal operation the kernel allocates the lowest free fd so values
    ; stay well below MAX_FDS, but a leak or burst could push past.  Close
    ; oversize fds rather than OOB-write conn_state (which would clobber
    ; events_buf / ctrl_fd / epoll_fd / phase counters).
    cmp     eax, MAX_FDS
    jae     .reject_fd

    ; reset state.buf_pos for this fd (fd may be a reused number)
    movsxd  rcx, eax
    imul    rcx, rcx, STATE_SIZE
    lea     rdx, [conn_state]
    mov     dword [rdx + rcx + STATE_BUF_POS], 0

    ; epoll_ctl(ADD, fd, EPOLLIN | EPOLLRDHUP)
    ; Level-triggered: busy-poll spin guarantees we re-observe buffered data
    ; on the next ~200 ns poll cycle without needing the EAGAIN drain loops.
    mov     dword [rsp + 4], EPOLLIN | EPOLLRDHUP
    mov     [rsp + 8], eax
    mov     edi, [epoll_fd]
    mov     esi, EPOLL_CTL_ADD
    mov     edx, eax
    lea     r10, [rsp + 4]
    syscall0 SYS_epoll_ctl

    inc     r13d
    jmp     .add_loop

.reject_fd:
    ; Oversize fd — close locally and continue (no epoll_ctl ADD, so no
    ; later DEL is needed).  Preserves r12/r13 (callee-save under SysV).
    mov     edi, eax
    syscall0 SYS_close
    inc     r13d
    jmp     .add_loop

.done:
    add     rsp, 288
    pop     r13
    pop     r12
    pop     rbx
    ret

; ---- handle_client_event --------------------------------------------------
; Drains an EPOLLET client fd: recv into conn_state[fd].buf until EAGAIN,
; frames complete HTTP requests inline, handles them, sends the response
; via send_all (blocking).  On EOF / error / oversized payload, removes
; the fd from epoll and closes.
;   edi = fd
;
; Stack frame: 2 pushes (rbx + rbp) + sub 24 → rsp 0 mod 16 before any CALL.
;   entry rsp%16 = 8 (after CALL pushed return addr) → 2 pushes (16 B) →
;   rsp%16 = 8 still → sub 24 → rsp%16 = 0 ✓
;   Slots used: [+0]body_off, [+4]body_len, [+8]total, [+12]out_len (16B).
;   Remaining 8B is padding to keep CALL alignment.
;
;   Note: parse_request / vectorize / search internally re-align via
;   `and rsp, -64`, so they didn't crash on the previous misaligned frame.
;   But http_frame uses xmm14/15 in `vmovd`/`vpbroadcastb` (unaligned-safe)
;   and pads via push, so no #GP either.  The bug was elsewhere — but the
;   ABI demands alignment regardless.

handle_client_event:
    push    rbx                          ; fd
    push    rbp                          ; state ptr
    sub     rsp, 24

    mov     ebx, edi
    movsxd  rax, ebx
    imul    rax, rax, STATE_SIZE
    lea     rbp, [conn_state]
    add     rbp, rax

.recv_more:
    mov     ecx, [rbp + STATE_BUF_POS]
    cmp     ecx, BUF_SIZE
    jae     .close                       ; buffer full — oversized request

    mov     edi, ebx
    lea     rsi, [rbp + rcx]
    mov     edx, BUF_SIZE
    sub     edx, ecx                       ; nbytes available
    mov     r10d, MSG_DONTWAIT
    xor     r8, r8                         ; src_addr  (NULL — don't peek)
    xor     r9, r9                         ; addrlen
    syscall0 SYS_recvfrom
    test    rax, rax
    jz      .close                        ; EOF
    js      .recv_err
%ifdef INSTRUMENT
    inc     qword [rel phase_recvfrom_cnt]
%endif

    ; CRITICAL: SYSCALL clobbers rcx (kernel writes RIP_after_syscall into
    ; rcx and rflags into r11 — Intel SDM, SYSCALL semantics).  Reload
    ; buf_pos from memory; using the stale ecx as the running counter was
    ; a long-standing bug that corrupted STATE_BUF_POS with the next-PC
    ; value, making http_frame parse phantom requests.
    mov     ecx, [rbp + STATE_BUF_POS]
    add     ecx, eax
    mov     [rbp + STATE_BUF_POS], ecx

.frame_loop:
    mov     edx, [rbp + STATE_BUF_POS]
    test    edx, edx
    jz      .recv_more

    ; http_frame(buf, total, &body_off, &body_len) → eax = bytes consumed
    ; or 0 if partial frame (need more bytes).
    mov     rdi, rbp                      ; buf at offset 0 of state
    mov     esi, edx
    lea     rdx, [rsp + 0]                ; &body_off
    lea     rcx, [rsp + 4]                ; &body_len
    call    http_frame
    test    eax, eax
    jz      .recv_more                    ; partial — wait for more

    mov     [rsp + 8], eax                ; consumed

    ; handle_request(buf, total, body_off, body_len, &out_len) → rax = ptr
    mov     rdi, rbp
    mov     esi, eax
    mov     edx, [rsp + 0]
    mov     ecx, [rsp + 4]
    lea     r8,  [rsp + 12]
    call    handle_request

    ; send_all(fd, response, out_len)
    mov     edi, ebx
    mov     rsi, rax
    mov     edx, [rsp + 12]
    call    send_all
    test    eax, eax
    js      .close                        ; send error → drop connection

    ; Shift any leftover bytes (pipelined request) to start of buffer.
    mov     ecx, [rbp + STATE_BUF_POS]
    mov     eax, [rsp + 8]                ; consumed
    sub     ecx, eax
    jz      .all_consumed
    ; memmove(buf, buf + consumed, remaining)
    push    rcx
    mov     rdi, rbp
    movsxd  r9, eax
    lea     rsi, [rbp + r9]
    movsxd  rcx, ecx
    cld
    rep     movsb
    pop     rcx
    mov     [rbp + STATE_BUF_POS], ecx
    jmp     .frame_loop

.all_consumed:
    mov     dword [rbp + STATE_BUF_POS], 0
    ; Under level-triggered epoll + busy-poll, if the kernel queue still has
    ; pipelined-request bytes for this fd, the next epoll_wait(0) (≤ 200 ns
    ; away inside server_loop_epoll's spin) will re-fire EPOLLIN for it.
    ; That makes the trailing drain recvfrom (which usually just returns
    ; EAGAIN) redundant — drop it to skip 1 syscall per request on the hot
    ; path.  Saves ~30-50 µs/req measured (varies by load).
    jmp     .ret

.recv_err:
    ; EWOULDBLOCK == EAGAIN on Linux — single check covers both.
    cmp     rax, -EAGAIN
    je      .ret
    cmp     rax, -EINTR
    je      .recv_more
    ; fall through → close

.close:
    ; epoll_ctl(DEL) is implicit on close(), but explicit DEL guards against
    ; a stale event already sitting in events_buf that we'd dispatch later.
    mov     edi, [epoll_fd]
    mov     esi, EPOLL_CTL_DEL
    mov     edx, ebx
    xor     r10, r10
    syscall0 SYS_epoll_ctl

    mov     edi, ebx
    syscall0 SYS_close

    mov     dword [rbp + STATE_BUF_POS], 0

.ret:
    add     rsp, 24
    pop     rbp
    pop     rbx
    ret

; ---- server_loop_epoll ----------------------------------------------------
; Single-threaded event loop, kernel-side busy poll edition.
;
; Previously this loop spun on epoll_wait(timeout=0) up to SPIN_BUDGET=256
; times before falling back to a blocking wait — burning ~50% of CPU on
; syscall framework overhead (entry_SYSRETQ + seccomp + FPU restore).
;
; With EPIOCSPARAMS (set on the epoll at startup, Linux 6.9+), the kernel
; busy-polls NAPI for 50 µs INSIDE every epoll_wait before sleeping.  We
; thus collapse the userspace spin into a SINGLE epoll_wait(timeout=1ms)
; per iteration:
;   - if an event arrives in the kernel busy-poll window → return < 50 µs
;   - else sleep for up to 1 ms (CFS-friendly)
;
; This trades ~256 syscalls per idle window (≈2.5 ms framework / spin)
; for ~1 syscall (≈10 µs framework / spin).  Pre-6.9 kernels treat the
; ioctl as ENOTTY and behave as if the busy-poll knob were never set —
; equivalent to the old blocking-only path.
;
; ctrl_fd was already added to the epoll set by _start.

server_loop_epoll:
    push    rbx                          ; n events
    push    r12                          ; iter i
    sub     rsp, 8                       ; align (2 push + 8 + ret = 32 → 0 mod 16)

.outer:
    mov     edi, [epoll_fd]
    lea     rsi, [events_buf]
    mov     edx, MAX_EVENTS
    mov     r10d, 1                      ; 1 ms timeout; kernel busy-polls 50 µs first
    syscall0 SYS_epoll_wait
    cmp     rax, -EINTR
    je      .outer
    test    rax, rax
    jle     .outer                       ; error or timeout — just retry

    mov     ebx, eax
    xor     r12d, r12d
.ev_loop:
    cmp     r12d, ebx
    jge     .outer

    movsxd  rax, r12d
    imul    rax, rax, EPOLL_EV_SIZE
    lea     rdx, [events_buf]
    mov     edi, [rdx + rax + EPOLL_EV_FD]

    cmp     edi, [ctrl_fd]
    je      .h_ctrl
    call    handle_client_event
    jmp     .next
.h_ctrl:
    call    handle_ctrl_event
.next:
    inc     r12d
    jmp     .ev_loop

%define WARM_REQ_ITERS 1000

warm_handle_request:
    push    rbx                          ; iter counter; rsp now 0 mod 16
    sub     rsp, 16                      ; out_len slot (4) + pad

    xor     ebx, ebx
.loop:
    cmp     ebx, WARM_REQ_ITERS
    jge     .done

    lea     rdi, [warm_http_req]
    mov     esi, warm_http_len           ; total
    mov     edx, warm_body_off
    mov     ecx, warm_body_len
    lea     r8, [rsp + 0]                ; &out_len
    call    handle_request
    ; Returned (rax, *out_len) are intentionally ignored.

    inc     ebx
    jmp     .loop

.done:
    add     rsp, 16
    pop     rbx
    ret

; ---- warm_dummy_syscalls -------------------------------------------------
; Issues a small batch of throwaway syscalls so the kernel paths they touch
; are resident before the real workload starts.  The three picked here —
; epoll_create1 + epoll_wait(timeout=0), pipe2, write/read on a unidirectional
; pipe — cover epoll, the generic file_table allocator, and the cheap
; kernel-only write/read paths.  Network syscalls (socket/recvfrom/sendto)
; are warmed for real by the LB's clone3 self-warm.

warm_dummy_syscalls:
    push    rbx
    sub     rsp, 80                      ; pipefd[2] (8) + epoll_event (12) + scratch (60)

    ; epoll_create1(EPOLL_CLOEXEC); epoll_wait(fd, &ev, 1, 0); close(fd)
    mov     edi, EPOLL_CLOEXEC
    syscall0 SYS_epoll_create1
    test    rax, rax
    js      .skip_epoll
    mov     ebx, eax

    mov     edi, ebx
    lea     rsi, [rsp + 16]
    mov     edx, 1
    xor     r10d, r10d
    syscall0 SYS_epoll_wait

    mov     edi, ebx
    syscall0 SYS_close
.skip_epoll:

    ; pipe2(pipefd, O_NONBLOCK|O_CLOEXEC); write 64 B; read 64 B; close both.
    lea     rdi, [rsp + 0]
    mov     esi, O_NONBLOCK | O_CLOEXEC
    syscall0 SYS_pipe2
    test    rax, rax
    js      .done

    mov     edi, [rsp + 4]               ; pipefd[1]
    lea     rsi, [rsp + 16]
    mov     edx, 64
    syscall0 SYS_write

    mov     edi, [rsp + 0]               ; pipefd[0]
    lea     rsi, [rsp + 16]
    mov     edx, 64
    syscall0 SYS_read

    mov     edi, [rsp + 4]
    syscall0 SYS_close
    mov     edi, [rsp + 0]
    syscall0 SYS_close

.done:
    add     rsp, 80
    pop     rbx
    ret

; ---- warm_index ----------------------------------------------------------
; Pre-touches the index by issuing 64 synthetic searches.  Pseudo-random
; queries cover most clusters once each.  No args, no return.

warm_index:
    push    rbx                          ; iteration counter; rsp now 0 mod 16
    sub     rsp, 48                      ; Query (32B) + slack; rsp still 0 mod 16

    ; Iteration budget: 10 000 synthetic searches at startup.  ~500 ms of
    ; pure CPU during boot, completely outside the timed test window.  Trains
    ; the branch predictor, populates all ~2048 cluster pair-array hot lines
    ; in L2/L3, fully resolves the index TLB, and primes the kernel page
    ; cache.  No detection regression — these are throwaway queries.
    xor     ebx, ebx
.loop:
    cmp     ebx, 10000
    jge     .done

    ; Zero the 32-byte Query slot
    pxor    xmm0, xmm0
    movdqu  [rsp + 0],  xmm0
    movdqu  [rsp + 16], xmm0

    ; Fill v[0..13] with (i*313 + d*1009) mod SCALE → i16.  Pseudo-random
    ; covers many distinct cluster paths over 10 k iterations.
    xor     ecx, ecx
.fill:
    cmp     ecx, N_DIMS
    jge     .fill_done
    mov     eax, ebx
    imul    eax, eax, 313
    mov     edx, ecx
    imul    edx, edx, 1009
    add     eax, edx
    cdq
    mov     edi, SCALE
    idiv    edi
    mov     [rsp + rcx*2], dx
    inc     ecx
    jmp     .fill
.fill_done:

    ; warm: cycle through all 4 partitions so each one's pair_arrays + bpsoa
    ; pages get touched during boot.  Use ebx & 3 as the rotating index.
    mov     eax, ebx
    and     eax, N_PARTITIONS - 1
    imul    eax, eax, IX_SIZE
    lea     rdi, [g_indices]
    add     rdi, rax
    mov     rsi, rsp
    call    search                       ; ignore return

    inc     ebx
    jmp     .loop

.done:
    add     rsp, 48
    pop     rbx
    ret

; ---- emit_hex_u64 ---------------------------------------------------------
; Writes 16 ASCII hex chars (big-endian, fixed width, no prefix) for the
; qword in rax into [rdi..rdi+15]; advances rdi by 16.  Clobbers rax, rcx,
; rdx, r8.  Used by dump_stats only — not on the request hot path.

emit_hex_u64:
    mov     rcx, 16
    lea     r8,  [rel dbg_hex]
.lp:
    mov     rdx, rax
    shr     rdx, 60
    and     edx, 0xF
    mov     dl,  [r8 + rdx]
    mov     [rdi], dl
    inc     rdi
    shl     rax, 4
    dec     rcx
    jnz     .lp
    ret

; ---- dump_stats -----------------------------------------------------------
; Writes one line to stderr (fd 2) with the current per-phase counters:
;   STATS p=HHHHHHHHHHHHHHHH pn=... f=... fn=... v=... vn=... s=... sn=...
;          w=... wn=... rm=... rf=... t=... tn=...\n
; 16-char zero-padded hex per field.  Total formatted line = 280 B (14 hex
; fields × 19-or-20 B + 1 B newline).  Called once per 1024 POSTs from
; handle_request — never on hot path.

dump_stats:
    ; Entry rsp = 8 mod 16 (per SysV).  Sub 296 = 304-8 lands rsp at 0 mod 16
    ; so the inner CALLs to emit_hex_u64 are properly aligned.  Buffer area
    ; is 296 B (formatted line is 280 B, +16 B headroom for future fields).
    sub     rsp, 296

    ; Layout the line in [rsp..rsp+280).  Headers are 8-byte stores so each
    ; mov writes "STATS p=", " pn=    ", etc. in one go (label + 16 hex).
    lea     rdi, [rsp]

    mov     rax, 0x3D70205354415453   ; "STATS p="
    mov     [rdi], rax
    add     rdi, 8
    mov     rax, [rel phase_parse_cyc]
    call    emit_hex_u64

    mov     eax, 0x3D6E7020           ; " pn="
    mov     [rdi], eax
    add     rdi, 4
    mov     rax, [rel phase_parse_cnt]
    call    emit_hex_u64

    mov     eax, 0x3D6620             ; " f="
    mov     [rdi], eax
    add     rdi, 3
    mov     rax, [rel phase_fp_cyc]
    call    emit_hex_u64

    mov     eax, 0x3D6E6620           ; " fn="
    mov     [rdi], eax
    add     rdi, 4
    mov     rax, [rel phase_fp_cnt]
    call    emit_hex_u64

    mov     eax, 0x3D7620             ; " v="
    mov     [rdi], eax
    add     rdi, 3
    mov     rax, [rel phase_vec_cyc]
    call    emit_hex_u64

    mov     eax, 0x3D6E7620           ; " vn="
    mov     [rdi], eax
    add     rdi, 4
    mov     rax, [rel phase_vec_cnt]
    call    emit_hex_u64

    mov     eax, 0x3D7320             ; " s="
    mov     [rdi], eax
    add     rdi, 3
    mov     rax, [rel phase_search_cyc]
    call    emit_hex_u64

    mov     eax, 0x3D6E7320           ; " sn="
    mov     [rdi], eax
    add     rdi, 4
    mov     rax, [rel phase_search_cnt]
    call    emit_hex_u64

    ; "w" = write/sendto cycles, "wn" = sendto count.  Per-syscall sendto
    ; latency = w/wn measures the kernel-side response-write cost without
    ; the ptrace overhead that inflated the strace-measured 37-158 µs.
    mov     eax, 0x3D7720             ; " w="
    mov     [rdi], eax
    add     rdi, 3
    mov     rax, [rel phase_send_cyc]
    call    emit_hex_u64

    mov     eax, 0x3D6E7720           ; " wn="
    mov     [rdi], eax
    add     rdi, 4
    mov     rax, [rel phase_send_cnt]
    call    emit_hex_u64

    ; " rm=" recvmsg count, " rf=" recvfrom count.  Ratio rf/rm = HTTP reqs
    ; per connection (keep-alive reuse).  High ratio = handoff batching low ROI.
    mov     eax, 0x3D6D7220           ; " rm="
    mov     [rdi], eax
    add     rdi, 4
    mov     rax, [rel phase_recvmsg_cnt]
    call    emit_hex_u64

    mov     eax, 0x3D667220           ; " rf="
    mov     [rdi], eax
    add     rdi, 4
    mov     rax, [rel phase_recvfrom_cnt]
    call    emit_hex_u64

    mov     eax, 0x3D7420             ; " t="
    mov     [rdi], eax
    add     rdi, 3
    mov     rax, [rel phase_total_cyc]
    call    emit_hex_u64

    mov     eax, 0x3D6E7420           ; " tn="
    mov     [rdi], eax
    add     rdi, 4
    mov     rax, [rel phase_total_cnt]
    call    emit_hex_u64

    mov     byte [rdi], 10            ; '\n'
    inc     rdi

    ; write(2, rsp, rdi - rsp)
    mov     rdx, rdi
    sub     rdx, rsp
    mov     rsi, rsp
    mov     edi, 2
    syscall0 SYS_write

    add     rsp, 296
    ret

; ---- _start ---------------------------------------------------------------
; Entry: rsp → argc, then argv[0..argc-1], NULL, envp[..], NULL.
;   argv[1]: UDS path (required)
;   argv[2]: index path (optional, defaults to "index.bin")

global _start
_start:
    mov     r12, [rsp]                   ; argc
    cmp     r12, 2
    jl      .usage

    mov     r14, [rsp + 16]              ; argv[1] = UDS path
    ; argv[2] is no longer used (4 per-partition indices loaded from
    ; hard-coded default paths).  Keep CLI compat: extra args ignored.

    ; Tighten this thread's timer slack from default 50 µs → 1 ns.  No cap
    ; required (a process can always shrink its own slack).  Cuts scheduler
    ; wake-up jitter on the response path.
    mov     edi, PR_SET_TIMERSLACK
    mov     esi, 1
    xor     edx, edx
    xor     r10, r10
    xor     r8, r8
    syscall0 SYS_prctl

    ; Pin every page resident — MCL_FUTURE covers the index mmap that follows.
    ; Best-effort: returns -EPERM/-ENOMEM when CAP_IPC_LOCK or RLIMIT_MEMLOCK
    ; refuses; ignored so the server still starts without elevated caps.
    mov     edi, MCL_CURRENT | MCL_FUTURE
    syscall0 SYS_mlockall

    ; Hint THP to back the 4.2 MB conn_state region with 2 MB hugepages.
    ; Reduces dTLB pressure on the per-fd state lookups (1024 4K pages →
    ; 2-3 hugepage entries).  Best-effort: kernel may decline if THP is
    ; disabled or fragmentation prevents collapse — return value ignored.
    lea     rdi, [conn_state]
    mov     esi, MAX_FDS * STATE_SIZE
    mov     edx, MADV_HUGEPAGE
    syscall0 SYS_madvise

    ; Promote this thread to SCHED_FIFO so an inbound packet wakes us above
    ; any SCHED_OTHER context (client, softirq).  Best-effort: needs CAP_SYS_NICE
    ; — silently falls back to SCHED_OTHER if not granted.
    sub     rsp, 16
    mov     dword [rsp + 0], WORKER_RT_PRIO
    xor     edi, edi                       ; pid = 0 → self
    mov     esi, SCHED_FIFO
    lea     rdx, [rsp + 0]
    syscall0 SYS_sched_setscheduler
    add     rsp, 16

    ; (sched_setaffinity removed — on the Mac Mini target the cgroup
    ; cpuset already constrains us to one physical core's two HT siblings,
    ; and pinning to a single sibling forced api1 and lb to serialize on
    ; CPU 0.  Letting the kernel balance within the cpuset lets api1 and
    ; lb run in parallel on HT siblings of the same physical core, with
    ; shared L1d giving lb→api fd-passing a warm cache.)

    call    mcc_init

    ; Open all 4 partition indices into g_indices[0..3].  Any failure
    ; aborts startup — partitioned routing requires all 4 present.
    xor     r13d, r13d                       ; partition iter i
.open_loop:
    cmp     r13d, N_PARTITIONS
    jge     .open_done
    mov     eax, r13d
    imul    eax, eax, IX_SIZE
    lea     rdi, [g_indices]
    add     rdi, rax                         ; &g_indices[i]
    lea     rax, [default_index_paths]
    mov     rsi, [rax + r13*8]               ; path string
    push    r13                              ; preserve across call
    call    index_open
    pop     r13
    test    eax, eax
    js      .fail_index
    inc     r13d
    jmp     .open_loop
.open_done:

    ; Warm path, ordered cheapest → hottest so the L1i / branch predictors
    ; end up primed with the production request flow (the last thing run):
    ;   1. warm_dummy_syscalls — exercises non-network kernel paths
    ;      (epoll/pipe/read/write) the rest of the warm-up doesn't hit.
    ;   2. warm_index — 10 000 synthetic searches; forces every bbox +
    ;      cluster pair-array page into L3 + kernel page cache, resolves
    ;      the index TLB.
    ;   3. warm_handle_request — 1 000 iterations of the full POST pipeline
    ;      (parse + vectorize + search + format) so by t=0 the predictor
    ;      tables and L1i mirror exactly what the first real request sees.
    call    warm_dummy_syscalls
    call    warm_index
    call    warm_handle_request

    ; Reset instrumentation counters so the first STATS dump reflects only
    ; live traffic (the 1000 warm POSTs above would otherwise dominate the
    ; first 1024-bucket sample).
    xor     eax, eax
    mov     [rel phase_parse_cyc],  rax
    mov     [rel phase_parse_cnt],  rax
    mov     [rel phase_fp_cyc],     rax
    mov     [rel phase_fp_cnt],     rax
    mov     [rel phase_vec_cyc],    rax
    mov     [rel phase_vec_cnt],    rax
    mov     [rel phase_search_cyc], rax
    mov     [rel phase_search_cnt], rax
    mov     [rel phase_send_cyc],   rax
    mov     [rel phase_send_cnt],   rax
    mov     [rel phase_recvmsg_cnt],rax
    mov     [rel phase_recvfrom_cnt],rax
    mov     [rel phase_total_cyc],  rax
    mov     [rel phase_total_cnt],  rax

    mov     rdi, r14
    call    bind_control_uds
    test    eax, eax
    js      .fail_bind
    mov     [ctrl_fd], eax

    ; Make ctrl_fd non-blocking so the edge-triggered drain in
    ; handle_ctrl_event terminates on EAGAIN rather than blocking the
    ; whole event loop.
    mov     edi, [ctrl_fd]
    mov     esi, F_SETFL
    mov     edx, O_NONBLOCK
    syscall0 SYS_fcntl

    ; epoll setup
    mov     edi, EPOLL_CLOEXEC
    syscall0 SYS_epoll_create1
    test    eax, eax
    js      .fail_bind
    mov     [epoll_fd], eax

    ; ioctl(epfd, EPIOCSPARAMS, &epoll_busy_params)  [Linux 6.9+, best-effort].
    ; Tells the kernel to NAPI-busy-poll for 50µs inside every epoll_wait
    ; before sleeping.  Failure (ENOTTY on pre-6.9 or EINVAL) is harmless —
    ; we just fall back to standard wake semantics.
    mov     edi, [epoll_fd]
    mov     esi, EPIOCSPARAMS
    lea     rdx, [epoll_busy_params]
    syscall0 SYS_ioctl

    sub     rsp, 16
    ; Level-triggered (no EPOLLET): the busy-poll spin in server_loop_epoll
    ; samples epoll_wait every ~200 ns, so any buffered data is observed on
    ; the immediate next poll — eliminating the need for drain-until-EAGAIN
    ; loops in handle_ctrl_event / handle_client_event (saves 1-2 syscalls
    ; per request that just returned EAGAIN anyway).
    mov     dword [rsp + 0], EPOLLIN
    mov     eax, [ctrl_fd]
    mov     [rsp + 4], eax
    mov     edi, [epoll_fd]
    mov     esi, EPOLL_CTL_ADD
    mov     edx, eax
    lea     r10, [rsp + 0]
    syscall0 SYS_epoll_ctl
    add     rsp, 16
    test    eax, eax
    js      .fail_bind

    call    server_loop_epoll

    xor     edi, edi
    syscall0 SYS_exit_group

.usage:
    mov     edi, STDERR
    lea     rsi, [usage_msg]
    mov     edx, usage_msg_len
    syscall0 SYS_write
    mov     edi, 1
    syscall0 SYS_exit_group

.fail_index:
    mov     edi, STDERR
    lea     rsi, [err_index_msg]
    mov     edx, err_index_msg_len
    syscall0 SYS_write
    mov     edi, 1
    syscall0 SYS_exit_group

.fail_bind:
    mov     edi, STDERR
    lea     rsi, [err_bind_msg]
    mov     edx, err_bind_msg_len
    syscall0 SYS_write
    mov     edi, 1
    syscall0 SYS_exit_group

section .note.GNU-stack noalloc noexec nowrite progbits
