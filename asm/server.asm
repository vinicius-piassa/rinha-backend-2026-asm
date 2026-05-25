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
%include "uring.inc"
%include "trace.inc"

extern parse_request

; Search sub-phase counters (defined in search.asm).
extern g_search_cp_sum, g_search_pick_sum, g_search_pick_count
extern g_search_scan_sum, g_search_scan_count
extern vectorize
extern search
extern mcc_init
extern index_open
extern uring_init
extern uring_submit_and_wait
extern uring_submit_no_wait
extern uring_register_files
extern uring_register_pbuf_ring

%define BUF_SIZE         4096
%define MAX_FDS          1024
%define STATE_SIZE       4104          ; buf(4096) + buf_pos(4) + 4 pad
%define STATE_BUF_POS    4096
%define MAX_EVENTS       64
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
%define IX_SIZE              120

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

err_resp:
    db "HTTP/1.1 400 Bad Request", 13, 10, "Content-Length: 0", 13, 10, 13, 10
err_resp_len   equ $ - err_resp

; Lowercase reference for case-insensitive Content-Length header detection.
str_cl_lower: db "content-length:"           ; 15 bytes; no NUL

default_index_path: db "index.bin", 0
usage_msg:          db "usage: asm-server <uds_path> [index_path]", 10
usage_msg_len  equ $ - usage_msg
err_index_msg:      db "error: failed to open index", 10
err_index_msg_len equ $ - err_index_msg
err_bind_msg:       db "error: bind_control_uds failed", 10
err_bind_msg_len  equ $ - err_bind_msg
dbg_hex:        db "0123456789ABCDEF"

; Trace dump markers (8-byte each so binary scanners can grep them).
align 8
trace_srv_magic:    db "TRC_SRV1"
trace_srv_end:      db "END_SRV", 10
trace_srv_path:     db "/traces/dump.bin", 0

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

; ===========================================================================
section .bss

; Read-only after server startup populates it (via index_open / external).
global g_index
alignb 8
g_index:    resb IX_SIZE

alignb 16
conn_state: resb MAX_FDS * STATE_SIZE       ; ~4.2 MB; indexed by fd
events_buf: resb MAX_EVENTS * EPOLL_EV_SIZE ; unused now (kept for the
                                            ; old epoll-based code that the
                                            ; linker drops via --gc-sections)
ctrl_fd:    resd 1
epoll_fd:   resd 1
; Set to 1 after the first GET /ready completes its re-warm pass.  Keeps the
; handler fast on every subsequent /ready poll the engine might issue.
ready_warm_done: resb 1

; io_uring state.  The Ring struct itself is 128 B; the recvmsg layout
; below is reused across multishot completions, with the kernel rewriting
; both the iov buffer and the cmsg control buffer in place each time.
alignb 64
g_ring:     resb URING_SIZE

; Registered file table.  Slot 0 = ctrl_fd (LB → API control channel).
; Client fds are NOT registered (they live too briefly to amortise the
; IORING_REGISTER_FILES_UPDATE overhead).
%define API_REG_CTRL_IDX  0
alignb 4
reg_files:  resd 1

; Provided-buffer ring for multishot recv on client fds.
;   - BUF_RING_ENTRIES must be a power of two.  Entry 0 is also the head of
;     the ring (the `tail` field lives at offset 14 of entry 0), but its
;     buffer payload is still usable as long as we always write the tail
;     AFTER publishing the buffer contents on x86's TSO model.
;   - Each buffer is BUF_SIZE bytes (4 KiB), enough for a single HTTP
;     request including headers.
;   - bgid = 0 (only one buffer group).
;   - IORING_REGISTER_PBUF_RING requires page-aligned ring memory.
%define BUF_RING_ENTRIES   256
%define BUF_RING_MASK      (BUF_RING_ENTRIES - 1)
%define BUF_RING_BGID      0
alignb 4096
buf_ring:   resb BUF_RING_ENTRIES * BUF_ENTRY_SIZE
alignb 4096
buf_pool:   resb BUF_RING_ENTRIES * BUF_SIZE
alignb 4
buf_ring_tail_cached: resd 1

; Multishot recvmsg state for ctrl_fd → fd-batches from the LB.
;   iobuf  — single-byte iov target (LB sends 'F' marker)
;   iov    — struct iovec { iobuf, 1 }
;   cmsg   — control buffer.  Linux 6.14+ kernels prepend an SO_PASSRIGHTS
;           (cmsg_type = 84) housekeeping block before the SCM_RIGHTS that
;           we asked for.  Each block costs CMSG_SPACE(4) = 24 B, so 256 B
;           gives us comfortable headroom whatever the kernel emits.
;   hdr    — struct msghdr the kernel re-fills on each recv
alignb 16
recvmsg_iobuf:    resb 16
recvmsg_iov:      resb 16
recvmsg_cmsg:     resb 256
recvmsg_hdr:      resb 56

; 4K-aliasing guard: forbid the recvmsg control plane and the per-request
; instrumentation counters from landing at the same page offset.  Bits 0-11
; of two recent load/store addresses match → Haswell predicts a false
; dependency and emits a machine-clear (~15-25 cycles).  128 B is enough to
; bump the next block past the aliasing window.
alignb 64
g_alias_pad_a:    resb 128

; ---------------------------------------------------------------------------
; Instrumentation state.  Lives in .bss so it's zero-initialised.  All fields
; are accessed single-threaded from handle_request / server_loop_uring; no
; atomics needed.
; ---------------------------------------------------------------------------
alignb 64
g_srv_req_count:    resq 1               ; POST requests completed
g_srv_enter_count:  resq 1               ; io_uring_enter calls
g_srv_parse_sum:    resq 1               ; sum of parse_request cycles
g_srv_vec_sum:      resq 1               ; sum of vectorize cycles
g_srv_search_sum:   resq 1               ; sum of search cycles
g_srv_handle_sum:   resq 1               ; sum of total handle_request cycles
g_srv_enter_sum:    resq 1               ; sum of cycles spent in submit_and_wait
g_srv_pad_a:        resq 1               ; align cursor section
g_srv_cursor:       resd 1               ; sample index
g_srv_pad0:         resd 1

alignb 64
g_srv_parse_ring:   resq TRACE_N
g_srv_search_ring:  resq TRACE_N
g_srv_handle_ring:  resq TRACE_N
g_srv_enter_ring:   resq TRACE_N

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
    jmp     .digit_loop

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
    xor     ecx, ecx                     ; i = 0
.crlf_scan:
    mov     rax, rcx
    add     rax, 3
    cmp     rax, r13
    jge     .no_crlf                     ; i + 3 < len? need: i + 3 < len → i+3 ≤ len-1 → i+3 < len
    ; Strict less-than: we need 4 bytes at offsets i..i+3.
    cmp     byte [rbx + rcx], 13
    jne     .crlf_next
    cmp     byte [rbx + rcx + 1], 10
    jne     .crlf_next
    cmp     byte [rbx + rcx + 2], 13
    jne     .crlf_next
    cmp     byte [rbx + rcx + 3], 10
    jne     .crlf_next
    lea     r14, [rbx + rcx]             ; he = buf + i
    jmp     .have_he
.crlf_next:
    inc     rcx
    jmp     .crlf_scan

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

    ; --- POST? (total >= 5 && buf[0..3] == "POST") ------------------------
    cmp     rbp, 5
    jl      .check_get
    cmp     dword [rbx], 0x54534F50      ; bytes 'P','O','S','T' little-endian
    jne     .check_get

    ; --- POST path ---------------------------------------------------------
    ; Stash body_len in r13 high half before parse zeroes Request (need rcx
    ; later but it survives all the SIMD/mov-imm below).  Take req_start TSC
    ; right here so all phase deltas roll up cleanly.
    mov     [rsp + 96], ecx              ; save body_len (scratch zone)
    TRACE_TSC qword [rsp + 104]          ; req_start_tsc; clobbers rax/rdx/rcx
    mov     ecx, [rsp + 96]              ; restore body_len

    ; Zero Request (72 B).
    pxor    xmm0, xmm0
    movdqu  [rsp + 0],  xmm0
    movdqu  [rsp + 16], xmm0
    movdqu  [rsp + 32], xmm0
    movdqu  [rsp + 48], xmm0
    mov     qword [rsp + 64], 0          ; 8 bytes covers mcc+is_online..known_merchant (8 bytes)

    ; parse_request(buf + body_off, body_len, &req)
    mov     [rsp + 96], ecx              ; spill body_len across TSC clobber
    TRACE_TSC qword [rsp + 112]          ; phase_start = parse start
    mov     ecx, [rsp + 96]
    lea     rdi, [rbx + r13]             ; buf + body_off
    movsxd  rsi, ecx                     ; body_len
    lea     rdx, [rsp + 0]               ; &req
    call    parse_request
    mov     [rsp + 96], eax              ; spill parse return (need test below)
    TRACE_PHASE_RING g_srv_parse_ring, g_srv_parse_sum, g_srv_cursor, qword [rsp + 112]
    mov     eax, [rsp + 96]
    test    eax, eax
    jnz     .post_err                    ; parse_request != 0 → 400

    ; vectorize(&req, &q)
    TRACE_TSC qword [rsp + 112]
    lea     rdi, [rsp + 0]
    lea     rsi, [rsp + 72]
    call    vectorize
    TRACE_PHASE_SUM g_srv_vec_sum, qword [rsp + 112]

    ; fraud = search(&g_index, &q)
    TRACE_TSC qword [rsp + 112]
    lea     rdi, [g_index]
    lea     rsi, [rsp + 72]
    call    search
    mov     [rsp + 96], al               ; spill search return (1 byte fits)
    TRACE_PHASE_RING g_srv_search_ring, g_srv_search_sum, g_srv_cursor, qword [rsp + 112]
    movzx   eax, byte [rsp + 96]         ; fraud
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
    ; Record handle_request total + bump cursor (may fire dump on the last
    ; sample).  Spill rax (response ptr) before TRACE clobbers it.
    mov     [rsp + 96], rax
    TRACE_PHASE_RING g_srv_handle_ring, g_srv_handle_sum, g_srv_cursor, qword [rsp + 104]
    TRACE_COUNT g_srv_req_count
    TRACE_BUMP g_srv_cursor, trace_dump_server, 4096
    mov     rax, [rsp + 96]
    jmp     .ret

.post_err:
    lea     rax, [err_resp]
    mov     dword [r12], err_resp_len
    jmp     .ret

.check_get:
    cmp     rbp, 4
    jl      .err
    cmp     word [rbx], 0x4547           ; "GE"
    jne     .err
    cmp     byte [rbx + 2], 'T'
    jne     .err

    ; First GET /ready triggers an additional warm pass — the engine's
    ; health probe is the last hop before k6 fires its first request, so
    ; refreshing the BPU + L1d/L1i tables here keeps the first batch of
    ; real requests off cold-cache p99 outliers.  Once-only (flag in bss);
    ; subsequent /ready polls return instantly.
    cmp     byte [ready_warm_done], 0
    jne     .skip_ready_warm
    mov     byte [ready_warm_done], 1
    call    warm_handle_request
.skip_ready_warm:

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

; ---- trace_dump_server ----------------------------------------------------
; Single-shot dump of all instrumentation state to fd 1 (stdout).  Layout:
;
;   [8B]  magic "TRC_SRV1"
;   [48B] 6 × u64 counters  (req, enter, parse_sum, vec_sum, search_sum, handle_sum)
;   [8B]  u32 cursor + u32 pad
;   [32K] g_srv_parse_ring   (TRACE_N × u64)
;   [32K] g_srv_search_ring  (TRACE_N × u64)
;   [32K] g_srv_handle_ring  (TRACE_N × u64)
;   [8B]  end marker "END_SRV\n"
;
; Total ~98 KB.  Called once by TRACE_BUMP when cursor hits TRACE_DONE_AT.

trace_dump_server:
    push    rbx                          ; saved file fd
    sub     rsp, 8                       ; align

    ; open("/traces/dump.bin", O_WRONLY|O_CREAT|O_TRUNC, 0644)
    lea     rdi, [rel trace_srv_path]
    mov     esi, O_WRONLY | O_CREAT | O_TRUNC
    mov     edx, 0o644
    syscall0 SYS_open
    test    rax, rax
    js      .done                         ; open failed — bind-mount missing
    mov     ebx, eax

    mov     edi, ebx
    lea     rsi, [rel trace_srv_magic]
    mov     edx, 8
    mov     eax, SYS_write
    syscall

    mov     edi, ebx
    lea     rsi, [rel g_srv_req_count]
    mov     edx, 64                       ; 8 × u64 counters (incl. enter_sum + pad)
    mov     eax, SYS_write
    syscall

    mov     edi, ebx
    lea     rsi, [rel g_srv_cursor]
    mov     edx, 8
    mov     eax, SYS_write
    syscall

    mov     edi, ebx
    lea     rsi, [rel g_srv_parse_ring]
    mov     edx, TRACE_N * 8
    mov     eax, SYS_write
    syscall

    mov     edi, ebx
    lea     rsi, [rel g_srv_search_ring]
    mov     edx, TRACE_N * 8
    mov     eax, SYS_write
    syscall

    mov     edi, ebx
    lea     rsi, [rel g_srv_handle_ring]
    mov     edx, TRACE_N * 8
    mov     eax, SYS_write
    syscall

    mov     edi, ebx
    lea     rsi, [rel g_srv_enter_ring]
    mov     edx, TRACE_N * 8
    mov     eax, SYS_write
    syscall

    ; Search sub-phase counters (5 × u64, contiguous in search.asm bss).
    mov     edi, ebx
    lea     rsi, [rel g_search_cp_sum]
    mov     edx, 40
    mov     eax, SYS_write
    syscall

    mov     edi, ebx
    lea     rsi, [rel trace_srv_end]
    mov     edx, 8
    mov     eax, SYS_write
    syscall

    mov     edi, ebx
    syscall0 SYS_close

.done:
    add     rsp, 8
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

    mov     ebx, edi
    mov     rbp, rsi
    movsxd  r12, edx
    xor     r13d, r13d

.loop:
    cmp     r13, r12
    jge     .done

    mov     edi, ebx                     ; fd
    lea     rsi, [rbp + r13]             ; p + off
    mov     rdx, r12
    sub     rdx, r13                     ; n - off
    mov     r10d, MSG_NOSIGNAL
    xor     r8d, r8d                     ; addr = NULL
    xor     r9d, r9d                     ; addrlen = 0
    syscall0 SYS_sendto

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
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret

.err:
    mov     eax, -1
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
    ; recvmsg(ctrl_fd, &msg, 0)
    mov     edi, ebx
    lea     rsi, [rsp + 128]
    xor     edx, edx
    syscall0 SYS_recvmsg
    cmp     rax, -EINTR
    je      .retry
    test    rax, rax
    js      .err
    jz      .eof

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
    jb      .walk_done                   ; malformed
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

; ---- setup_client_fd ------------------------------------------------------
; void setup_client_fd(int fd);
;   Configure TCP_NODELAY+TCP_QUICKACK, register in epoll, reset per-fd state.
;   Returns 0 OK / -1 on error.  Caller may ignore the return (best-effort).

setup_client_fd:
    push    rbx                          ; fd
    sub     rsp, 16                       ; locals: optval(4) + epoll_event(12)
    mov     ebx, edi

    mov     dword [rsp + 0], 1            ; optval = 1

    ; setsockopt(fd, SOL_TCP, TCP_NODELAY, &one, 4)
    ; NB: syscall arg4 lives in r10, NOT rcx — `syscall` clobbers rcx/r11.
    mov     edi, ebx
    mov     esi, SOL_TCP
    mov     edx, TCP_NODELAY
    lea     r10, [rsp + 0]
    mov     r8d, 4
    syscall0 SYS_setsockopt

    ; setsockopt(fd, SOL_TCP, TCP_QUICKACK, &one, 4)
    mov     edi, ebx
    mov     esi, SOL_TCP
    mov     edx, TCP_QUICKACK
    lea     r10, [rsp + 0]
    mov     r8d, 4
    syscall0 SYS_setsockopt

    ; TCP_NOTSENT_LOWAT = 128 — kernel only signals the socket as writable
    ; once <128 bytes are unacked.  For our short responses this prevents
    ; buffer bloat that would slow down the first ACK.
    mov     dword [rsp + 0], 128
    mov     edi, ebx
    mov     esi, SOL_TCP
    mov     edx, TCP_NOTSENT_LOWAT
    lea     r10, [rsp + 0]
    mov     r8d, 4
    syscall0 SYS_setsockopt

    mov     dword [rsp + 0], 1            ; restore optval=1 for later writes

    ; fcntl(fd, F_SETFL, O_NONBLOCK) — required by edge-triggered epoll.
    ; In ET mode, recv must be drained until -EAGAIN; that only works on a
    ; non-blocking fd, otherwise the first drained byte blocks the thread.
    mov     edi, ebx
    mov     esi, F_SETFL
    mov     edx, O_NONBLOCK
    syscall0 SYS_fcntl

    ; epoll_event { events=EPOLLIN | EPOLLET | EPOLLRDHUP, data.fd=fd }.
    ;   EPOLLET   — edge-triggered: one CQE per readability transition.
    ;               Cuts wake-up syscall count under load.
    ;   EPOLLRDHUP — earlier detection of peer half-close; saves one extra
    ;               recv→0→close round trip when the client disconnects.
    mov     dword [rsp + 0], EPOLLIN | EPOLLET | EPOLLRDHUP
    mov     qword [rsp + 4], 0
    mov     dword [rsp + 4], ebx          ; data.fd

    mov     edi, [epoll_fd]
    mov     esi, EPOLL_CTL_ADD
    mov     edx, ebx
    lea     r10, [rsp + 0]
    syscall0 SYS_epoll_ctl
    test    rax, rax
    js      .err

    ; conn_state[fd].buf_pos = 0
    movsxd  rax, ebx
    imul    rax, rax, STATE_SIZE
    lea     rdi, [conn_state]
    add     rdi, rax
    mov     dword [rdi + STATE_BUF_POS], 0

    xor     eax, eax
    add     rsp, 16
    pop     rbx
    ret

.err:
    mov     eax, -1
    add     rsp, 16
    pop     rbx
    ret

; ---- close_client_fd ------------------------------------------------------
; void close_client_fd(int fd);
;   epoll_ctl_del + close + reset state.buf_pos.

close_client_fd:
    push    rbx
    mov     ebx, edi

    mov     edi, [epoll_fd]
    mov     esi, EPOLL_CTL_DEL
    mov     edx, ebx
    xor     r10, r10
    syscall0 SYS_epoll_ctl

    mov     edi, ebx
    syscall0 SYS_close

    movsxd  rax, ebx
    imul    rax, rax, STATE_SIZE
    lea     rdi, [conn_state]
    add     rdi, rax
    mov     dword [rdi + STATE_BUF_POS], 0

    pop     rbx
    ret

; ---- handle_ctrl_event ----------------------------------------------------
; int handle_ctrl_event(int ctrl_fd);
;   Drains one batch of fds from ctrl_fd via recv_client_fds; registers each.
;   Returns 0 OK / -1 transient error / -2 EOF (LB closed → server should stop).

handle_ctrl_event:
    push    rbx
    push    r12
    push    r13
    sub     rsp, 64                       ; 8 fds + 4 nfds + pad (rsp 0 mod 16)
    mov     ebx, edi

    mov     edi, ebx
    lea     rsi, [rsp + 0]
    mov     edx, 8
    lea     rcx, [rsp + 48]               ; &nfds at safe offset (avoid overlap)
    call    recv_client_fds
    test    eax, eax
    js      .err
    jz      .eof

    mov     r13d, [rsp + 48]              ; nfds
    xor     r12d, r12d
.fd_loop:
    cmp     r12d, r13d
    jge     .ok
    mov     edi, [rsp + r12*4]
    call    setup_client_fd
    inc     r12d
    jmp     .fd_loop

.ok:
    xor     eax, eax
    jmp     .ret
.eof:
    mov     eax, -2
    jmp     .ret
.err:
    mov     eax, -1
.ret:
    add     rsp, 64
    pop     r13
    pop     r12
    pop     rbx
    ret

; ---- handle_client_event --------------------------------------------------
; void handle_client_event(int fd);
;   Drain loop for an edge-triggered epoll event:  loop recv() until the
;   kernel signals -EAGAIN; for every successful read, parse pipelined HTTP
;   frames and emit responses.  Must drain fully — under EPOLLET, a leftover
;   byte in the socket buffer waits forever because no new readiness event
;   will fire until further bytes arrive.
;   On EOF or hard error: close + epoll_del + reset state.

handle_client_event:
    push    rbx                          ; fd
    push    rbp                          ; state ptr
    push    r12                          ; buf base
    push    r13                          ; buf_pos cache
    sub     rsp, 32                       ; locals:
                                         ;   [+0]  body_off
                                         ;   [+4]  body_len
                                         ;   [+8]  total
                                         ;   [+12] out_len
                                         ;   [+16] leftover scratch

    mov     ebx, edi

    movsxd  rax, ebx
    imul    rax, rax, STATE_SIZE
    lea     rbp, [conn_state]
    add     rbp, rax
    mov     r12, rbp                     ; buf base (state starts with buf)
    mov     r13d, [rbp + STATE_BUF_POS]

.recv_loop:
    ; If the buffer is full but no frame parsed, refuse to grow (we'd recurse
    ; forever).  This is the abort path for an oversized request.
    cmp     r13d, BUF_SIZE
    jge     .close

    ; recv(fd, buf + buf_pos, BUF_SIZE - buf_pos, MSG_DONTWAIT) — the
    ; MSG_DONTWAIT mirrors the O_NONBLOCK flag we already set; either
    ; produces -EAGAIN when the socket is dry, which is our "drained" signal.
    mov     edi, ebx
    lea     rsi, [rbp + r13]
    mov     edx, BUF_SIZE
    sub     edx, r13d
    mov     r10d, MSG_DONTWAIT
    xor     r8, r8
    xor     r9, r9
    syscall0 SYS_recvfrom

    test    rax, rax
    js      .check_err
    jz      .close                        ; EOF — peer closed cleanly

    add     r13d, eax
    mov     [rbp + STATE_BUF_POS], r13d

.drain:
    mov     rdi, r12
    mov     esi, r13d
    lea     rdx, [rsp + 0]
    lea     rcx, [rsp + 4]
    call    http_frame
    test    eax, eax
    jz      .recv_loop                    ; partial frame; recv more bytes

    mov     [rsp + 8], eax               ; total

    mov     rdi, r12
    mov     esi, eax
    mov     edx, [rsp + 0]
    mov     ecx, [rsp + 4]
    lea     r8, [rsp + 12]
    call    handle_request

    mov     edi, ebx
    mov     rsi, rax
    mov     edx, [rsp + 12]
    call    send_all
    test    eax, eax
    jnz     .close

    ; leftover = buf_pos - total
    mov     eax, [rsp + 8]
    mov     r13d, [rbp + STATE_BUF_POS]
    sub     r13d, eax
    mov     [rsp + 16], r13d
    test    r13d, r13d
    jz      .reset_pos

    movsxd  rdx, eax
    lea     rsi, [r12 + rdx]
    mov     rdi, r12
    movsxd  rcx, r13d
    cld
    rep     movsb

.reset_pos:
    mov     r13d, [rsp + 16]
    mov     [rbp + STATE_BUF_POS], r13d
    jmp     .drain                        ; check for another full frame
                                          ; already in the buffer (pipeline)

.check_err:
    cmp     rax, -EAGAIN
    je      .ret                          ; drained — wait for next ET event
    cmp     rax, -EINTR
    je      .recv_loop                    ; transient — retry
    jmp     .close

.close:
    mov     edi, ebx
    call    close_client_fd

.ret:
    add     rsp, 32
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret

; ---- server_loop ----------------------------------------------------------
; void server_loop(int ctrl_fd);
;   Runs epoll_wait → dispatch indefinitely until ctrl LB hangs up.

server_loop:
    push    rbx                          ; ctrl_fd
    push    rbp                          ; event index
    push    r12                          ; n events
    sub     rsp, 8                       ; rsp now 0 mod 16

    mov     ebx, edi

.outer:
    mov     edi, [epoll_fd]
    lea     rsi, [events_buf]
    mov     edx, MAX_EVENTS
    mov     r10d, -1
    syscall0 SYS_epoll_wait
    test    rax, rax
    js      .check_eintr

    mov     r12d, eax
    xor     ebp, ebp

.ev_loop:
    cmp     ebp, r12d
    jge     .outer

    movsxd  rax, ebp
    imul    rax, rax, EPOLL_EV_SIZE
    lea     rcx, [events_buf]
    mov     edi, [rcx + rax + EPOLL_EV_FD]    ; fd from event.data.fd

    cmp     edi, ebx
    jne     .client

    call    handle_ctrl_event
    cmp     eax, -2
    je      .stop
    jmp     .next_ev
.client:
    call    handle_client_event
.next_ev:
    inc     ebp
    jmp     .ev_loop

.check_eintr:
    cmp     rax, -EINTR
    je      .outer
    ; other error - bail out

.stop:
    add     rsp, 8
    pop     r12
    pop     rbp
    pop     rbx
    ret

; ===========================================================================
; io_uring server loop
; ===========================================================================

; ---- get_next_sqe ---------------------------------------------------------
; Returns rax = pointer to the next free SQE in the ring; advances the
; cached tail.  Returns rax = 0 if the ring is full (caller must submit
; first).  Pure compute, no syscall.
;
; No args; reads/writes g_ring.

get_next_sqe:
    ; tail = ring.tail_cached;  head = *ring.sq_head
    mov     eax, [g_ring + URING_SQ_TAIL_CACHED]
    mov     rcx, [g_ring + URING_SQ_HEAD]
    mov     edx, [rcx]
    ; if tail - head == sq_entries → full.  We allocated 256 slots; mask
    ; works out to (tail - head) > mask → full.
    mov     ecx, eax
    sub     ecx, edx
    cmp     ecx, [g_ring + URING_SQ_MASK]
    ja      .full

    ; slot = tail & mask
    mov     ecx, eax
    and     ecx, [g_ring + URING_SQ_MASK]
    shl     ecx, SQE_SHIFT
    mov     rdx, [g_ring + URING_SQES]
    lea     rax, [rdx + rcx]              ; sqe ptr

    ; tail_cached++
    inc     dword [g_ring + URING_SQ_TAIL_CACHED]
    ret

.full:
    xor     eax, eax
    ret

; ---- arm_ctrl_recvmsg -----------------------------------------------------
; Re-arm (or first-arm) the multishot recvmsg on ctrl_fd.  Idempotent —
; the msghdr/iov/cmsg buffers are reused across iterations, the kernel
; just overwrites their content.
;
;   edi = ctrl_fd

arm_ctrl_recvmsg:
    push    rbx
    mov     ebx, edi

    ; Initialise iov[0] once: { iobuf, 1 }
    lea     rax, [recvmsg_iobuf]
    mov     [recvmsg_iov + 0], rax
    mov     qword [recvmsg_iov + 8], 1

    ; Zero msghdr (56 B → 64 covered by two 32-byte stores)
    vpxor   xmm0, xmm0, xmm0
    vmovdqu [recvmsg_hdr + 0],  xmm0
    vmovdqu [recvmsg_hdr + 16], xmm0
    vmovdqu [recvmsg_hdr + 32], xmm0

    ; Fields: msg_iov (+16), msg_iovlen (+24), msg_control (+32),
    ; msg_controllen (+40); name/namelen left zero.
    lea     rax, [recvmsg_iov]
    mov     [recvmsg_hdr + 16], rax
    mov     qword [recvmsg_hdr + 24], 1
    lea     rax, [recvmsg_cmsg]
    mov     [recvmsg_hdr + 32], rax
    mov     qword [recvmsg_hdr + 40], 256

    call    get_next_sqe
    test    rax, rax
    jz      .nosqe                        ; ring full → caller will retry later

    ; Single-shot recvmsg against the registered ctrl_fd (slot 0).  Multishot
    ; recvmsg would need an IORING_REGISTER_PBUF_RING (kernel consumes
    ; provided buffers instead of msghdr's iov) and returns -EINVAL without
    ; one — leading to a re-arm loop.  Re-arming once per fd batch is only
    ; ~one SQE per accepted connection, negligible.
    SQE_ZERO rax
    mov     byte [rax + SQE_OPCODE], IORING_OP_RECVMSG
    mov     byte [rax + SQE_FLAGS], IOSQE_FIXED_FILE
    mov     dword [rax + SQE_FD], API_REG_CTRL_IDX
    lea     rcx, [recvmsg_hdr]
    mov     [rax + SQE_ADDR], rcx
    ; user_data = UD_OP_RECVMSG | ctrl_fd (kept for diagnostics)
    mov     rcx, UD_OP_RECVMSG
    mov     edx, ebx
    or      rcx, rdx
    mov     [rax + SQE_USER_DATA], rcx

.nosqe:
    pop     rbx
    ret

; ---- init_buf_ring -------------------------------------------------------
; Pre-fills the provided-buffer ring with every entry of buf_pool, registers
; the ring with the kernel, then publishes the initial tail.  Called once
; at startup after uring_init.  Returns eax = 0 OK / -1 on register error.

init_buf_ring:
    ; Publish entries 0..BUF_RING_ENTRIES-1.  Entry 0's payload sits in the
    ; same 16 B as the io_uring_buf_ring head/tail metadata, but the kernel
    ; only reads addr/len/bid from buf entries (offsets 0..13) and treats
    ; offset 14..15 as the tail; those reads don't overlap so the dual use
    ; is safe.  The final tail write must happen AFTER all buf data is in
    ; place — x86 TSO guarantees that.
    xor     ecx, ecx
.fill:
    cmp     ecx, BUF_RING_ENTRIES
    jge     .fill_done
    mov     eax, ecx
    shl     eax, BUF_ENTRY_SHIFT          ; * 16
    lea     rdi, [buf_ring]
    add     rdi, rax                      ; entry ptr
    mov     eax, ecx
    shl     eax, 12                       ; * 4096 = BUF_SIZE
    lea     rdx, [buf_pool]
    add     rdx, rax                      ; buf addr
    mov     [rdi + BUF_ADDR], rdx
    mov     dword [rdi + BUF_LEN], BUF_SIZE
    mov     word [rdi + BUF_BID], cx
    mov     word [rdi + BUF_RESV], 0
    inc     ecx
    jmp     .fill
.fill_done:

    ; Publish initial tail BEFORE registering.  Tail field is at offset
    ; 14 of entry 0; entry 0 also carries a buffer payload, but that's
    ; fine because the kernel reads tail separately.  On x86 TSO this
    ; final write is a release-store.
    mov     word [buf_ring + 14], BUF_RING_ENTRIES
    mov     dword [buf_ring_tail_cached], BUF_RING_ENTRIES

    ; Register the ring.  buf_ring is the ring memory; entries count is
    ; BUF_RING_ENTRIES; bgid is BUF_RING_BGID.
    lea     rdi, [g_ring]
    lea     rsi, [buf_ring]
    mov     edx, BUF_RING_ENTRIES
    mov     ecx, BUF_RING_BGID
    call    uring_register_pbuf_ring
    test    eax, eax
    js      .fail

    xor     eax, eax
.fail:
    ret

; ---- publish_buffer ------------------------------------------------------
; Re-publishes one consumed buffer (by buf_id) back into the ring.  Caller
; passes edi = buf_id (0..BUF_RING_ENTRIES-1).  Pure compute, no syscall.

publish_buffer:
    ; slot = tail_cached & MASK
    mov     eax, [buf_ring_tail_cached]
    mov     ecx, eax
    and     ecx, BUF_RING_MASK
    shl     ecx, BUF_ENTRY_SHIFT
    lea     rdx, [buf_ring]
    add     rdx, rcx                     ; entry ptr

    ; addr = buf_pool + buf_id * BUF_SIZE
    mov     ecx, edi
    shl     ecx, 12                       ; * 4096
    lea     r8, [buf_pool]
    add     r8, rcx
    mov     [rdx + BUF_ADDR], r8
    mov     dword [rdx + BUF_LEN], BUF_SIZE
    mov     word [rdx + BUF_BID], di

    ; Advance tail (publish; tail field lives at buf_ring + 14)
    inc     eax
    mov     [buf_ring_tail_cached], eax
    mov     word [buf_ring + 14], ax
    ret

; ---- arm_client_recv ------------------------------------------------------
; Multishot recv with provided buffer ring.  One SQE keeps generating CQEs
; for every chunk of bytes arriving on fd; the kernel picks a buffer from
; bgid=0 for each completion.  CQE.flags carries the buf_id in the high 16
; bits and IORING_CQE_F_BUFFER as the marker.
;
;   edi = fd

arm_client_recv:
    push    rbx
    mov     ebx, edi

    call    get_next_sqe
    test    rax, rax
    jz      .nosqe

    SQE_ZERO rax
    mov     byte [rax + SQE_OPCODE], IORING_OP_RECV
    mov     byte [rax + SQE_FLAGS], IOSQE_BUFFER_SELECT
    mov     word [rax + SQE_IOPRIO], IORING_RECV_MULTISHOT
    mov     dword [rax + SQE_FD], ebx
    mov     word [rax + SQE_BUF_GROUP], BUF_RING_BGID
    mov     rcx, UD_OP_RECV
    mov     edx, ebx
    or      rcx, rdx
    mov     [rax + SQE_USER_DATA], rcx

.nosqe:
    pop     rbx
    ret

; ---- arm_client_send ------------------------------------------------------
; Submits a send for the response.  CQE_SKIP_SUCCESS keeps the CQ empty on
; the happy path (kernel only reports failures), so we never have to
; dispatch a SEND completion.
;
;   edi = fd, rsi = buf, edx = len

arm_client_send:
    push    rbx                          ; fd
    push    rbp                          ; buf
    push    r12                          ; len

    mov     ebx, edi
    mov     rbp, rsi
    mov     r12d, edx

    call    get_next_sqe
    test    rax, rax
    jz      .nosqe

    SQE_ZERO rax
    mov     byte [rax + SQE_OPCODE], IORING_OP_SEND
    mov     byte [rax + SQE_FLAGS], IOSQE_CQE_SKIP_SUCCESS
    mov     dword [rax + SQE_FD], ebx
    mov     [rax + SQE_ADDR], rbp
    mov     dword [rax + SQE_LEN], r12d
    mov     dword [rax + SQE_OP_FLAGS], MSG_NOSIGNAL
    mov     rcx, UD_OP_SEND
    mov     edx, ebx
    or      rcx, rdx
    mov     [rax + SQE_USER_DATA], rcx

.nosqe:
    pop     r12
    pop     rbp
    pop     rbx
    ret

; ---- arm_client_close -----------------------------------------------------
;   edi = fd

arm_client_close:
    push    rbx
    mov     ebx, edi
    call    get_next_sqe
    test    rax, rax
    jz      .nosqe
    SQE_ZERO rax
    mov     byte [rax + SQE_OPCODE], IORING_OP_CLOSE
    mov     dword [rax + SQE_FD], ebx
    mov     rcx, UD_OP_CLOSE
    mov     edx, ebx
    or      rcx, rdx
    mov     [rax + SQE_USER_DATA], rcx
.nosqe:
    pop     rbx
    ret

; ---- parse_cmsg_extract_fds -----------------------------------------------
; Walks one SCM_RIGHTS-bearing msg_control buffer and registers every fd
; with the io_uring loop (zero its conn_state buf_pos + submit recv).
;   rdi = msg_control ptr
;   esi = msg_controllen

parse_cmsg_extract_fds:
    push    rbx                          ; cmsg cursor
    push    rbp                          ; cmsg end

    mov     rbx, rdi
    movsxd  rbp, esi
    add     rbp, rbx                     ; end = ctrl + ctrllen

.walk:
    lea     rax, [rbx + 16]
    cmp     rax, rbp
    ja      .done

    mov     rdi, [rbx + 0]               ; cmsg_len
    cmp     rdi, 16
    jb      .done
    mov     eax, [rbx + 8]
    cmp     eax, SOL_SOCKET
    jne     .next
    mov     eax, [rbx + 12]
    cmp     eax, SCM_RIGHTS
    jne     .next

    ; n_fds = (cmsg_len - 16) / 4
    mov     r10, rdi
    sub     r10, 16
    shr     r10, 2
    lea     r11, [rbx + 16]              ; fds base
    xor     ecx, ecx
.fd_loop:
    cmp     ecx, r10d
    jge     .next
    mov     edi, [r11 + rcx*4]           ; fd

    ; Zero this fd's buf_pos before arming the recv.
    movsxd  rax, edi
    imul    rax, rax, STATE_SIZE
    lea     rdx, [conn_state]
    mov     dword [rdx + rax + STATE_BUF_POS], 0

    push    rcx
    push    r10
    push    r11
    call    arm_client_recv
    pop     r11
    pop     r10
    pop     rcx
    inc     ecx
    jmp     .fd_loop

.next:
    mov     rax, [rbx + 0]
    add     rax, 7
    and     rax, -8
    add     rbx, rax
    jmp     .walk

.done:
    pop     rbp
    pop     rbx
    ret

; ---- handle_recvmsg_cqe ---------------------------------------------------
; Called on every multishot recvmsg completion against ctrl_fd.  The kernel
; has refilled recvmsg_hdr/cmsg in place with the new batch's fds.
;   edi = ctrl_fd (low 32 of user_data)
;   esi = cqe.res
;   r8d = cqe.flags
; Returns eax: 0 normal, -2 if ctrl channel closed (LB hung up).

handle_recvmsg_cqe:
    push    rbx                          ; ctrl_fd
    push    r12                          ; saved cqe.flags
    sub     rsp, 8

    mov     ebx, edi
    mov     r12d, r8d

    test    esi, esi
    js      .err
    jz      .eof

    ; Walk cmsg from the actual controllen (may have shrunk).  msg_controllen
    ; sits at +40 of the kernel-rewritten msghdr.  Linux 6.14+ adds an
    ; SO_PASSRIGHTS housekeeping cmsg ahead of the SCM_RIGHTS we asked for,
    ; so parse_cmsg_extract_fds is built to skip unknown cmsg types.
    mov     rdi, [recvmsg_hdr + 32]      ; msg_control ptr (we set it; kernel doesn't change)
    mov     esi, dword [recvmsg_hdr + 40]
    call    parse_cmsg_extract_fds

    ; Single-shot: each completion drains one batch of fds; re-arm for the
    ; next batch.  IORING_CQE_F_MORE is never set on single-shot CQEs.
    mov     edi, ebx
    call    arm_ctrl_recvmsg

.ok:
    xor     eax, eax
    jmp     .ret
.eof:
    mov     eax, -2
    jmp     .ret
.err:
    ; recvmsg with a transient error (e.g. -EINTR).  Re-arm; if the channel
    ; is truly broken the next recvmsg returns 0 (EOF) which stops us.
    mov     edi, ebx
    call    arm_ctrl_recvmsg
    xor     eax, eax
.ret:
    add     rsp, 8
    pop     r12
    pop     rbx
    ret

; ---- handle_recv_cqe ------------------------------------------------------
; A multishot recv fired for a client fd.  CQE flags carry the buf_id in
; the high 16 bits + IORING_CQE_F_BUFFER as a marker (when bytes were
; copied) + IORING_CQE_F_MORE while the multishot is still armed.
;
; Lifecycle per CQE:
;   1. Extract buf_id; locate buf_addr in buf_pool.
;   2. If conn_state has accumulated bytes from a previous partial frame,
;      append the new bytes there and parse from conn_state; otherwise
;      parse directly from the kernel buffer (no memcpy on golden path).
;   3. For each complete frame: handle_request → send response.
;   4. Stash any tail partial into conn_state for the next CQE.
;   5. Re-publish the buffer back to the ring.
;   6. If the kernel cleared F_MORE (multishot ended), re-arm.
;
;   edi = fd, esi = res, r8d = cqe.flags

handle_recv_cqe:
    push    rbx                          ; fd
    push    rbp                          ; state ptr
    push    r12                          ; res
    push    r13                          ; buf_id
    push    r14                          ; work_buf
    push    r15                          ; cqe flags
    sub     rsp, 32                       ; locals:
                                         ;   [+0]  body_off
                                         ;   [+4]  body_len
                                         ;   [+8]  total
                                         ;   [+12] out_len
                                         ;   [+16] work_len

    mov     ebx, edi
    mov     r12d, esi
    mov     r15d, r8d

    movsxd  rax, ebx
    imul    rax, rax, STATE_SIZE
    lea     rbp, [conn_state]
    add     rbp, rax

    ; Compute buf_id and buf_addr only when F_BUFFER is set; otherwise the
    ; CQE carries no buffer (e.g., -ENOBUFS, EOF without payload).
    test    r15d, IORING_CQE_F_BUFFER
    jz      .check_status
    mov     r13d, r15d
    shr     r13d, IORING_CQE_BUFFER_SHIFT
    movzx   r13d, r13w
    mov     eax, r13d
    shl     eax, 12                       ; * 4096
    lea     r14, [buf_pool]
    add     r14, rax

.check_status:
    test    r12d, r12d
    js      .close                        ; recv error
    jz      .close                        ; EOF
    test    r15d, IORING_CQE_F_BUFFER
    jz      .close                        ; res>0 but no buffer would be a
                                          ; kernel anomaly — abort cleanly

    ; If conn_state holds a partial frame, append new bytes there.  Else
    ; parse directly from the kernel buffer (no memcpy on the golden path).
    mov     edx, [rbp + STATE_BUF_POS]
    test    edx, edx
    jnz     .accumulate

    mov     [rsp + 16], r12d              ; work_len = res
    jmp     .drain

.accumulate:
    push    rdx                          ; save buf_pos
    lea     rdi, [rbp + rdx]
    mov     rsi, r14
    movsxd  rcx, r12d
    cld
    rep     movsb
    pop     rdx
    add     edx, r12d
    mov     [rbp + STATE_BUF_POS], edx
    mov     r14, rbp                      ; work_buf = conn_state.buf
    mov     [rsp + 16], edx
    ; fallthrough

.drain:
    mov     edx, [rsp + 16]
    test    edx, edx
    jz      .all_consumed

    mov     rdi, r14
    mov     esi, edx
    lea     rdx, [rsp + 0]
    lea     rcx, [rsp + 4]
    call    http_frame
    test    eax, eax
    jz      .partial

    mov     [rsp + 8], eax

    mov     rdi, r14
    mov     esi, eax
    mov     edx, [rsp + 0]
    mov     ecx, [rsp + 4]
    lea     r8,  [rsp + 12]
    call    handle_request

    mov     edi, ebx
    mov     rsi, rax
    mov     edx, [rsp + 12]
    call    arm_client_send

    movsxd  rax, dword [rsp + 8]
    add     r14, rax
    mov     ecx, [rsp + 16]
    sub     ecx, eax
    mov     [rsp + 16], ecx
    jmp     .drain

.all_consumed:
    mov     dword [rbp + STATE_BUF_POS], 0
    jmp     .republish

.partial:
    mov     ecx, [rsp + 16]
    cmp     r14, rbp
    je      .partial_inplace
    cmp     ecx, BUF_SIZE
    jae     .close                        ; oversized partial → abort
    mov     rdi, rbp
    mov     rsi, r14
    movsxd  rdx, ecx
    push    rcx
    mov     rcx, rdx
    cld
    rep     movsb
    pop     rcx
    mov     [rbp + STATE_BUF_POS], ecx
    jmp     .republish
.partial_inplace:
    mov     [rbp + STATE_BUF_POS], ecx

.republish:
    mov     edi, r13d
    call    publish_buffer

    ; Re-arm multishot only if the kernel told us it ended (CQE_F_MORE
    ; clear).  Steady state pays zero submission cost.
    test    r15d, IORING_CQE_F_MORE
    jnz     .ret
    mov     edi, ebx
    call    arm_client_recv
    jmp     .ret

.close:
    ; Release any buffer the kernel gave us before closing.
    test    r15d, IORING_CQE_F_BUFFER
    jz      .close_no_buf
    mov     edi, r13d
    call    publish_buffer
.close_no_buf:
    mov     edi, ebx
    call    arm_client_close

.ret:
    add     rsp, 32
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret

; ---- handle_close_cqe -----------------------------------------------------
; A close SQE has completed.  Reset that fd's state so it's ready for reuse.
;   edi = fd

handle_close_cqe:
    movsxd  rax, edi
    imul    rax, rax, STATE_SIZE
    lea     rcx, [conn_state]
    mov     dword [rcx + rax + STATE_BUF_POS], 0
    ret

; ---- server_loop_uring ---------------------------------------------------
; The new main loop.  Drains all available CQEs, then submits+waits via
; uring_submit_and_wait.  Returns when the LB hangs up the ctrl channel.
;   edi = ctrl_fd

global server_loop_uring
server_loop_uring:
    push    rbx                          ; ctrl_fd
    push    rbp                          ; cqe iterator
    push    r12                          ; cqe pointer
    push    r13                          ; saved tail
    push    r14                          ; saved head
    push    r15                          ; cqes base + mask cache
    sub     rsp, 8                        ; rsp 0 mod 16

    mov     ebx, edi
    mov     [ctrl_fd], ebx                ; for completeness

    ; First arm
    mov     edi, ebx
    call    arm_ctrl_recvmsg

.outer:
    ; head = *cq_head, tail = *cq_tail
    mov     r15, [g_ring + URING_CQ_HEAD]
    mov     ebp, [r15]                    ; head
    mov     rax, [g_ring + URING_CQ_TAIL]
    mov     r13d, [rax]                   ; tail
    cmp     ebp, r13d
    je      .submit_wait

    mov     r14, [g_ring + URING_CQES]
    mov     r12d, [g_ring + URING_CQ_MASK]

.cqe_loop:
    cmp     ebp, r13d
    je      .drained

    ; cqe = cqes + (head & mask) * 16
    mov     eax, ebp
    and     eax, r12d
    shl     eax, CQE_SHIFT
    lea     rcx, [r14 + rax]              ; cqe

    ; Load user_data, res, flags
    mov     rax, [rcx + CQE_USER_DATA]
    mov     esi, [rcx + CQE_RES]
    mov     r8d, [rcx + CQE_FLAGS]

    ; Dispatch on op (high 32 bits).  fd is low 32 bits → rdi.
    mov     edi, eax                      ; fd
    shr     rax, 32                       ; op
    cmp     eax, UD_OP_RECV >> UD_OP_SHIFT
    je      .h_recv
    cmp     eax, UD_OP_RECVMSG >> UD_OP_SHIFT
    je      .h_recvmsg
    cmp     eax, UD_OP_SEND >> UD_OP_SHIFT
    je      .h_send
    cmp     eax, UD_OP_CLOSE >> UD_OP_SHIFT
    je      .h_close
    ; Unknown op — ignore.
    jmp     .next

.h_recv:
    call    handle_recv_cqe
    jmp     .next
.h_recvmsg:
    call    handle_recvmsg_cqe
    cmp     eax, -2
    je      .stop
    jmp     .next
.h_send:
    ; With IOSQE_CQE_SKIP_SUCCESS we only land here on send errors; force
    ; the fd closed so we don't get stuck holding a half-broken connection.
    test    esi, esi
    jns     .next
    call    arm_client_close
    jmp     .next
.h_close:
    call    handle_close_cqe
    ; fallthrough

.next:
    inc     ebp
    jmp     .cqe_loop

.drained:
    mov     [r15], ebp                    ; publish new cq head

.submit_wait:
    TRACE_COUNT g_srv_enter_count
    TRACE_TSC qword [rsp + 0]            ; pre-enter TSC into scratch slot
    lea     rdi, [g_ring]
    mov     esi, 1
    call    uring_submit_and_wait
    TRACE_PHASE_RING g_srv_enter_ring, g_srv_enter_sum, g_srv_cursor, qword [rsp + 0]
    ; -EINTR / transient: keep looping.  Any positive return is the count of
    ; SQEs the kernel ingested; ignored.
    jmp     .outer

.stop:
    mov     [r15], ebp
    add     rsp, 8
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret

; ---- warm_handle_request -------------------------------------------------
; Pre-runs the full handle_request pipeline (POST detect → parse_request →
; vectorize → search → format response) N times against a static request
; baked into .rodata.  Catches code paths that warm_index does not exercise
; — parse, vectorize, the POST branch of handle_request, the fraud_resp
; lookup table — so by the time the first real client arrives, both branch
; predictors and L1i are saturated with the production hot path.
;
; No I/O: handle_request is pure compute, so this is safe to run before
; the LB is even connected.

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

    lea     rdi, [g_index]
    mov     rsi, rsp
    call    search                       ; ignore return

    inc     ebx
    jmp     .loop

.done:
    add     rsp, 48
    pop     rbx
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

    mov     r14, [rsp + 16]              ; argv[1]
    cmp     r12, 3
    jl      .default_index
    mov     r15, [rsp + 24]              ; argv[2]
    jmp     .have_paths
.default_index:
    lea     r15, [default_index_path]
.have_paths:

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

    call    mcc_init

    lea     rdi, [g_index]
    mov     rsi, r15
    call    index_open
    test    eax, eax
    js      .fail_index

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

    ; Reset instrumentation state.  warm_index bypasses handle_request and
    ; bumps the search sub-phase counters with cold-cache synthetic queries
    ; (10x more expensive than real traffic), while warm_handle_request adds
    ; another 1000 iterations into the same counters.  Wipe everything so
    ; the dump only reflects real client traffic.
    xor     eax, eax
    mov     [rel g_srv_req_count], rax
    mov     [rel g_srv_enter_count], rax
    mov     [rel g_srv_parse_sum], rax
    mov     [rel g_srv_vec_sum], rax
    mov     [rel g_srv_search_sum], rax
    mov     [rel g_srv_handle_sum], rax
    mov     [rel g_srv_enter_sum], rax
    mov     dword [rel g_srv_cursor], 0
    mov     [rel g_search_cp_sum], rax
    mov     [rel g_search_pick_sum], rax
    mov     [rel g_search_pick_count], rax
    mov     [rel g_search_scan_sum], rax
    mov     [rel g_search_scan_count], rax

    mov     rdi, r14
    call    bind_control_uds
    test    eax, eax
    js      .fail_bind
    mov     [ctrl_fd], eax

    ; io_uring path (multishot accept + multishot recv + provided buffer
    ; ring + registered files).
    lea     rdi, [g_ring]
    mov     esi, 256
    call    uring_init
    test    eax, eax
    js      .fail_bind

    mov     eax, [ctrl_fd]
    mov     [reg_files + API_REG_CTRL_IDX*4], eax
    lea     rdi, [g_ring]
    lea     rsi, [reg_files]
    mov     edx, 1
    call    uring_register_files
    test    eax, eax
    js      .fail_bind

    call    init_buf_ring
    test    eax, eax
    js      .fail_bind

    mov     edi, [ctrl_fd]
    call    server_loop_uring

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
