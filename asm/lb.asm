; Load balancer: TCP listener that hands accepted client fds to API processes
; over Unix sockets with SCM_RIGHTS.  No HTTP byte proxying — once sendmsg()
; returns, the API owns the client connection end-to-end.
;
; Usage: ./asm_lb <port> <uds_path1> [uds_path2] ...
;
; Architecture (single-thread epoll):
;   listen TCP <port>                           (non-blocking)
;   for each backend UDS path: connect (retry until ready)
;   epoll_ctl_add tcp_listen_fd
;   loop:
;     epoll_wait
;     on tcp event: drain accept4 until EAGAIN; for each client_fd
;       setsockopt(TCP_NODELAY, TCP_QUICKACK)
;       send_fd to backends[rr_cursor++ % backend_count]
;       close(client_fd)   ; LB no longer owns it
;
; No health-mode (GET → 200 ready short-circuit) in v1 — backends start
; before LB ever accepts a client, so the retry loop in connect_backends
; handles startup; runtime health checks fall through to the backend.

bits 64
default rel

%include "syscalls.inc"
%include "macros.inc"
%include "uring.inc"

extern uring_init
extern uring_submit_and_wait
extern uring_register_files
extern uring_register_napi

%define MAX_BACKENDS    8
%define MAX_EVENTS      64
%define EPOLL_EV_SIZE   12
%define EPOLL_EV_FD     4
%define BACKEND_RETRIES 50
%define RETRY_SLEEP_NS  100000000   ; 100 ms

; ===========================================================================
section .rodata
usage_msg: db "usage: asm-lb <port> <uds_path1> [uds_path2 ...]", 10
usage_msg_len  equ $ - usage_msg
err_listen_msg: db "lb: listen_tcp failed", 10
err_listen_msg_len equ $ - err_listen_msg
err_backend_msg: db "lb: backend connect failed (gave up)", 10
err_backend_msg_len equ $ - err_backend_msg

; Static HTTP/POST + canonical JSON used by the forked self-warm child to
; round-trip real packets through the LB → SCM_RIGHTS → API → response
; pipeline before k6 hits us.  Bodies must stay byte-identical to the
; server's warm_body so a future schema change updates both copies together.
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
warm_body_len      equ warm_http_end - warm_body

%if warm_body_len != 407
    %error "warm_body_len != 407 — update the Content-Length header"
%endif

; ===========================================================================
section .bss
alignb 8
backends_fd:    resd MAX_BACKENDS
backend_paths:  resq MAX_BACKENDS
backend_count:  resd 1
rr_cursor:      resd 1
tcp_listen_fd:  resd 1
epoll_fd:       resd 1                          ; unused now (gc-sectioned)
events_buf:     resb MAX_EVENTS * EPOLL_EV_SIZE ; unused now

alignb 64
g_ring:         resb URING_SIZE

; Registered file table.  Index 0 = tcp_listen_fd; indices 1..N = backends_fd.
; Once registered with IORING_REGISTER_FILES, SQEs reference these slots via
; IOSQE_FIXED_FILE + slot index, which skips the per-syscall fd→struct file
; resolution in the kernel (~100-200 ns saved per submit).
%define REG_LISTEN_IDX   0
%define REG_BACKENDS_BASE 1
alignb 4
reg_files:      resd (MAX_BACKENDS + 1)

; Pool of sendmsg payload structures, cycled round-robin so the kernel can
; consume each one before we overwrite it.  Each 128-byte entry packs:
;   +0   iobuf  (1 used + 7 pad)
;   +8   iovec  (struct iovec, 16 B)
;   +24  cmsg   (CMSG_SPACE(sizeof(int)) = 24 B for one fd)
;   +48  msghdr (56 B)
;   +104 pad
%define MSGPOOL_SIZE     32                  ; power of 2
%define MSGPOOL_MASK     (MSGPOOL_SIZE - 1)
%define MSGPOOL_ENTRY    128
%define MSGPOOL_BYTES    (MSGPOOL_SIZE * MSGPOOL_ENTRY)
%define MP_IOBUF_OFF     0
%define MP_IOV_OFF       8
%define MP_CMSG_OFF      24
%define MP_MSGHDR_OFF    48
alignb 64
msgpool:        resb MSGPOOL_BYTES
msgpool_cursor: resd 1

; ===========================================================================
section .text

; ---- atoi -----------------------------------------------------------------
; eax = atoi(rdi)   (decimal, stops at non-digit / NUL)
atoi:
    xor     eax, eax
.l:
    movzx   ecx, byte [rdi]
    sub     ecx, '0'
    cmp     ecx, 9
    ja      .d
    lea     eax, [eax + eax*4]
    lea     eax, [ecx + eax*2]
    inc     rdi
    jmp     .l
.d:
    ret

; ---- listen_tcp -----------------------------------------------------------
; int listen_tcp(int port_host);
;   edi = port (host order)
;   Returns fd ≥ 0 or -1 on failure.
;   Sets SO_REUSEADDR; binds to 0.0.0.0:port; listen(4096); O_NONBLOCK.

listen_tcp:
    push    rbx                          ; fd
    push    rbp                          ; port
    sub     rsp, 24                       ; sockaddr_in(16) + optval(4) + pad

    mov     ebp, edi

    mov     edi, AF_INET
    mov     esi, SOCK_STREAM | SOCK_CLOEXEC
    xor     edx, edx
    syscall0 SYS_socket
    test    rax, rax
    js      .fail_nofd
    mov     rbx, rax

    ; setsockopt SO_REUSEADDR = 1
    ; NB: syscall arg4 lives in r10, NOT rcx — `syscall` clobbers rcx/r11.
    mov     dword [rsp + 16], 1
    mov     edi, ebx
    mov     esi, SOL_SOCKET
    mov     edx, SO_REUSEADDR
    lea     r10, [rsp + 16]
    mov     r8d, 4
    syscall0 SYS_setsockopt

    ; SO_REUSEPORT — lets the kernel split the listen queue across workers
    ; if we ever fork a second LB.  Best-effort here (no harm if alone).
    mov     edi, ebx
    mov     esi, SOL_SOCKET
    mov     edx, SO_REUSEPORT
    lea     r10, [rsp + 16]
    mov     r8d, 4
    syscall0 SYS_setsockopt

    ; TCP_DEFER_ACCEPT — kernel only marks the socket "readable" once the
    ; first byte of the request arrives.  Saves one accept→wait-for-recv
    ; round trip per connection; k6 always sends the POST immediately so
    ; the deferral never delays a real request.  Timeout=1 second is plenty.
    mov     dword [rsp + 16], 1
    mov     edi, ebx
    mov     esi, SOL_TCP
    mov     edx, TCP_DEFER_ACCEPT
    lea     r10, [rsp + 16]
    mov     r8d, 4
    syscall0 SYS_setsockopt

    ; sockaddr_in at [rsp + 0]
    pxor    xmm0, xmm0
    movdqu  [rsp + 0], xmm0
    mov     word [rsp + 0], AF_INET
    ; sin_port (BE) at offset 2
    mov     edx, ebp
    rol     dx, 8
    mov     [rsp + 2], dx
    ; sin_addr = 0 (INADDR_ANY) — already zeroed by pxor

    mov     edi, ebx
    lea     rsi, [rsp + 0]
    mov     edx, 16
    syscall0 SYS_bind
    test    rax, rax
    js      .fail_close

    mov     edi, ebx
    mov     esi, 4096
    syscall0 SYS_listen
    test    rax, rax
    js      .fail_close

    ; fcntl(fd, F_SETFL, O_NONBLOCK)
    mov     edi, ebx
    mov     esi, F_SETFL
    mov     edx, O_NONBLOCK
    syscall0 SYS_fcntl

    mov     rax, rbx
    add     rsp, 24
    pop     rbp
    pop     rbx
    ret

.fail_close:
    mov     edi, ebx
    syscall0 SYS_close
.fail_nofd:
    mov     eax, -1
    add     rsp, 24
    pop     rbp
    pop     rbx
    ret

; ---- connect_uds ----------------------------------------------------------
; int connect_uds(const char *path);
;   rdi = NUL-terminated path
;   Returns fd ≥ 0 or -1.  Single attempt; caller retries on -1.

connect_uds:
    push    rbx
    push    r12
    sub     rsp, 120                      ; sockaddr_un (110) + pad (10)

    mov     r12, rdi

    mov     edi, AF_UNIX
    mov     esi, SOCK_STREAM | SOCK_CLOEXEC
    xor     edx, edx
    syscall0 SYS_socket
    test    rax, rax
    js      .fail_nofd
    mov     rbx, rax

    ; Zero sockaddr_un (110 bytes)
    pxor    xmm0, xmm0
%assign O 0
%rep 7
    movdqu  [rsp + O], xmm0
%assign O O+16
%endrep
    mov     word [rsp + 0], AF_UNIX

    ; Copy path → sun_path
    lea     rdi, [rsp + 2]
    mov     rsi, r12
    mov     ecx, 107
.cp:
    test    ecx, ecx
    jz      .cp_done
    movzx   eax, byte [rsi]
    test    al, al
    jz      .cp_done
    mov     [rdi], al
    inc     rdi
    inc     rsi
    dec     ecx
    jmp     .cp
.cp_done:

    mov     edi, ebx
    mov     rsi, rsp
    mov     edx, 110
    syscall0 SYS_connect
    test    rax, rax
    js      .fail_close

    mov     rax, rbx
    add     rsp, 120
    pop     r12
    pop     rbx
    ret

.fail_close:
    mov     edi, ebx
    syscall0 SYS_close
.fail_nofd:
    mov     eax, -1
    add     rsp, 120
    pop     r12
    pop     rbx
    ret

; ---- send_fd --------------------------------------------------------------
; int send_fd(int uds_fd, int client_fd);
;   edi = uds_fd, esi = client_fd
;   Returns 0 OK / -1 on error.  Sends a 1-byte iov ('F') + cmsg(SCM_RIGHTS, 1 fd).

send_fd:
    push    rbx
    push    rbp
    sub     rsp, 104                      ; iobuf(8)+iov(16)+cmsg(24)+msghdr(56)

    mov     ebx, edi
    mov     ebp, esi

    ; iobuf at [rsp + 0]: { 'F' }
    mov     byte [rsp + 0], 'F'

    ; iovec at [rsp + 8]: { rsp+0, 1 }
    lea     rax, [rsp + 0]
    mov     [rsp + 8], rax
    mov     qword [rsp + 16], 1

    ; cmsg_buf at [rsp + 24]: cmsghdr + 1 fd (4 B) + pad to 24
    mov     qword [rsp + 24], 20         ; cmsg_len = CMSG_LEN(4) = 16 + 4
    mov     dword [rsp + 32], SOL_SOCKET
    mov     dword [rsp + 36], SCM_RIGHTS
    mov     dword [rsp + 40], ebp        ; payload = client_fd
    mov     dword [rsp + 44], 0          ; align tail

    ; msghdr at [rsp + 48]
    mov     qword [rsp + 48], 0          ; msg_name
    mov     qword [rsp + 56], 0          ; msg_namelen + pad
    lea     rax, [rsp + 8]
    mov     [rsp + 64], rax              ; msg_iov
    mov     qword [rsp + 72], 1          ; msg_iovlen
    lea     rax, [rsp + 24]
    mov     [rsp + 80], rax              ; msg_control
    mov     qword [rsp + 88], 24         ; msg_controllen
    mov     qword [rsp + 96], 0          ; msg_flags + pad

.retry:
    mov     edi, ebx
    lea     rsi, [rsp + 48]
    mov     edx, MSG_NOSIGNAL
    syscall0 SYS_sendmsg
    cmp     rax, -EINTR
    je      .retry
    test    rax, rax
    js      .err

    xor     eax, eax
    add     rsp, 104
    pop     rbp
    pop     rbx
    ret
.err:
    mov     eax, -1
    add     rsp, 104
    pop     rbp
    pop     rbx
    ret

; ---- accept_loop ----------------------------------------------------------
; void accept_loop(void);   reads globals: tcp_listen_fd, backends_fd[],
;                           backend_count, rr_cursor.
;
; Drains accept4 until EAGAIN; for each client_fd: setsockopt NODELAY+QUICKACK,
; send_fd to next round-robin backend, close client_fd locally.

accept_loop:
    push    rbx                          ; client fd
    sub     rsp, 8                        ; optval(4) + pad (rsp 0 mod 16)

.accept:
    mov     edi, [tcp_listen_fd]
    xor     esi, esi
    xor     edx, edx
    mov     r10d, SOCK_CLOEXEC
    syscall0 SYS_accept4
    test    rax, rax
    js      .check_err
    mov     ebx, eax

    mov     dword [rsp + 0], 1

    ; TCP_NODELAY  (syscall arg4 → r10, not rcx)
    mov     edi, ebx
    mov     esi, SOL_TCP
    mov     edx, TCP_NODELAY
    lea     r10, [rsp + 0]
    mov     r8d, 4
    syscall0 SYS_setsockopt

    ; TCP_QUICKACK
    mov     edi, ebx
    mov     esi, SOL_TCP
    mov     edx, TCP_QUICKACK
    lea     r10, [rsp + 0]
    mov     r8d, 4
    syscall0 SYS_setsockopt

    ; Pick backend: rr_cursor++ % backend_count
    mov     eax, [rr_cursor]
    inc     dword [rr_cursor]
    xor     edx, edx
    div     dword [backend_count]
    ; edx = backend index

    mov     edi, [backends_fd + rdx*4]
    mov     esi, ebx
    call    send_fd
    ; ignore send_fd error — proceed to close

    mov     edi, ebx
    syscall0 SYS_close

    jmp     .accept

.check_err:
    cmp     rax, -EINTR
    je      .accept
    cmp     rax, -EAGAIN
    je      .done
    ; other errors — bail out of this drain pass
.done:
    add     rsp, 8
    pop     rbx
    ret

; ---- server_loop ---------------------------------------------------------

server_loop:
    push    rbx                          ; n events
    sub     rsp, 8

.outer:
    mov     edi, [epoll_fd]
    lea     rsi, [events_buf]
    mov     edx, MAX_EVENTS
    mov     r10d, -1
    syscall0 SYS_epoll_wait
    test    rax, rax
    js      .check_eintr

    mov     ebx, eax
    xor     ecx, ecx
.ev_loop:
    cmp     ecx, ebx
    jge     .outer

    movsxd  rax, ecx
    imul    rax, rax, EPOLL_EV_SIZE
    lea     rdx, [events_buf]
    mov     edi, [rdx + rax + EPOLL_EV_FD]

    cmp     edi, [tcp_listen_fd]
    jne     .next
    call    accept_loop

.next:
    inc     ecx
    jmp     .ev_loop

.check_eintr:
    cmp     rax, -EINTR
    je      .outer
    add     rsp, 8
    pop     rbx
    ret

; ===========================================================================
; io_uring helpers — local to the LB.  Same shape as the server's helpers
; but operate against the LB's own g_ring.  No state machine per accept;
; we just submit sendmsg→close (hardlinked) and bounce.
; ===========================================================================

; ---- get_next_sqe (LB private) -------------------------------------------
; rax = next free SQE pointer; rax = 0 if SQ full.  Pure compute.

lb_get_next_sqe:
    mov     eax, [g_ring + URING_SQ_TAIL_CACHED]
    mov     rcx, [g_ring + URING_SQ_HEAD]
    mov     edx, [rcx]
    mov     ecx, eax
    sub     ecx, edx
    cmp     ecx, [g_ring + URING_SQ_MASK]
    ja      .full
    mov     ecx, eax
    and     ecx, [g_ring + URING_SQ_MASK]
    shl     ecx, SQE_SHIFT
    mov     rdx, [g_ring + URING_SQES]
    lea     rax, [rdx + rcx]
    inc     dword [g_ring + URING_SQ_TAIL_CACHED]
    ret
.full:
    xor     eax, eax
    ret

; ---- msgpool_init --------------------------------------------------------
; One-shot at LB start.  Walks every msgpool entry and pre-fills the
; pointer / length fields that never change across requests, so the
; per-request fast path only writes the client_fd into the cmsg payload
; and the destination uds_fd into the SQE.

msgpool_init:
    xor     ecx, ecx
.loop:
    cmp     ecx, MSGPOOL_SIZE
    jge     .done
    ; entry = msgpool + ecx*MSGPOOL_ENTRY
    mov     eax, ecx
    shl     eax, 7                        ; * 128
    lea     rdi, [msgpool]
    add     rdi, rax                      ; entry base

    ; iobuf[0] = 'F'
    mov     byte [rdi + MP_IOBUF_OFF], 'F'

    ; iov = { &iobuf, 1 }
    lea     rax, [rdi + MP_IOBUF_OFF]
    mov     [rdi + MP_IOV_OFF + 0], rax
    mov     qword [rdi + MP_IOV_OFF + 8], 1

    ; cmsg header (cmsg_len = 20, level = SOL_SOCKET, type = SCM_RIGHTS).
    ; Payload (fd) and the 4-byte alignment tail are filled per request.
    mov     qword [rdi + MP_CMSG_OFF + 0], 20
    mov     dword [rdi + MP_CMSG_OFF + 8], SOL_SOCKET
    mov     dword [rdi + MP_CMSG_OFF + 12], SCM_RIGHTS
    mov     dword [rdi + MP_CMSG_OFF + 16], 0
    mov     dword [rdi + MP_CMSG_OFF + 20], 0

    ; msghdr = { name=0, namelen=0, iov=&iov, iovlen=1, ctrl=&cmsg,
    ;            ctrllen=24, msg_flags=0 }
    mov     qword [rdi + MP_MSGHDR_OFF + 0], 0
    mov     qword [rdi + MP_MSGHDR_OFF + 8], 0   ; namelen + pad
    lea     rax, [rdi + MP_IOV_OFF]
    mov     [rdi + MP_MSGHDR_OFF + 16], rax
    mov     qword [rdi + MP_MSGHDR_OFF + 24], 1
    lea     rax, [rdi + MP_CMSG_OFF]
    mov     [rdi + MP_MSGHDR_OFF + 32], rax
    mov     qword [rdi + MP_MSGHDR_OFF + 40], 24
    mov     qword [rdi + MP_MSGHDR_OFF + 48], 0

    inc     ecx
    jmp     .loop
.done:
    ret

; ---- arm_accept ----------------------------------------------------------
; Posts a *multishot* accept against the registered tcp_listen_fd (file slot
; REG_LISTEN_IDX).  One SQE keeps generating CQEs for every incoming TCP
; connection until the kernel clears IORING_CQE_F_MORE — at which point the
; CQE handler re-arms.  Combined with IOSQE_FIXED_FILE, this is one of the
; biggest single wins of Nível 3: zero SQE submission per accept on the
; steady state, and the kernel skips fd→struct file lookup.

arm_accept:
    call    lb_get_next_sqe
    test    rax, rax
    jz      .nosqe

    SQE_ZERO rax
    mov     byte [rax + SQE_OPCODE], IORING_OP_ACCEPT
    mov     byte [rax + SQE_FLAGS], IOSQE_FIXED_FILE
    mov     word [rax + SQE_IOPRIO], IORING_ACCEPT_MULTISHOT
    mov     dword [rax + SQE_FD], REG_LISTEN_IDX
    mov     dword [rax + SQE_OP_FLAGS], SOCK_CLOEXEC
    ; user_data = UD_OP_ACCEPT | REG_LISTEN_IDX
    mov     rdx, UD_OP_ACCEPT
    or      rdx, REG_LISTEN_IDX
    mov     [rax + SQE_USER_DATA], rdx
.nosqe:
    ret

; ---- handle_accept_cqe ---------------------------------------------------
; A new client TCP connection has been accepted.  Configure TCP_NODELAY +
; TCP_QUICKACK on the fd (synchronous setsockopt — ~100 ns each), then
; submit sendmsg(SCM_RIGHTS, fd) hardlinked to close(fd) so the LB drops
; its local copy regardless of sendmsg's success.
;
;   edi = new client fd (from cqe.res)
;   r8d = cqe.flags (used only to decide whether to re-arm accept)

handle_accept_cqe:
    push    rbx                          ; client_fd
    push    rbp                          ; saved cqe flags
    sub     rsp, 24                       ; 4 (optval) + scratch + pad

    mov     ebx, edi
    mov     ebp, r8d

    test    ebx, ebx
    js      .recheck_more                ; negative result → some error

    ; --- setsockopt TCP_NODELAY + TCP_QUICKACK (synchronous; ~100 ns each)
    mov     dword [rsp + 0], 1
    mov     edi, ebx
    mov     esi, SOL_TCP
    mov     edx, TCP_NODELAY
    lea     r10, [rsp + 0]
    mov     r8d, 4
    syscall0 SYS_setsockopt

    mov     edi, ebx
    mov     esi, SOL_TCP
    mov     edx, TCP_QUICKACK
    lea     r10, [rsp + 0]
    mov     r8d, 4
    syscall0 SYS_setsockopt

    ; SO_BUSY_POLL on this fd was a no-op: LB never recv()s the accepted
    ; client socket — it sends it via SCM_RIGHTS and closes its copy.  The
    ; busy-poll property does NOT propagate through fd-passing in a way that
    ; benefits the receiver, so the option was 600 ns of dead syscall per
    ; accept.  The API gets busy-poll via IORING_REGISTER_NAPI on its uring
    ; instead, which is the kernel-supported path.

    ; --- pick a msgpool entry: idx = msgpool_cursor++ & MASK
    mov     eax, [msgpool_cursor]
    inc     dword [msgpool_cursor]
    and     eax, MSGPOOL_MASK
    shl     eax, 7                        ; * 128
    lea     r9, [msgpool]
    add     r9, rax                       ; entry base in r9
    mov     dword [r9 + MP_CMSG_OFF + 16], ebx ; payload = client_fd

    ; --- pick a backend: rr_cursor++ % backend_count → registered file index
    mov     eax, [rr_cursor]
    inc     dword [rr_cursor]
    xor     edx, edx
    div     dword [backend_count]
    add     edx, REG_BACKENDS_BASE        ; registered-file slot index
    mov     ecx, edx                      ; backend file index

    ; --- submit sendmsg SQE (linked to close)
    push    rcx                          ; backend file idx
    push    r9                           ; msgpool entry
    call    lb_get_next_sqe
    pop     r9
    pop     rcx
    test    rax, rax
    jz      .skip_close                  ; SQ full — drop client_fd via blocking close

    SQE_ZERO rax
    mov     byte [rax + SQE_OPCODE], IORING_OP_SENDMSG
    mov     byte [rax + SQE_FLAGS], IOSQE_IO_HARDLINK | IOSQE_CQE_SKIP_SUCCESS | IOSQE_FIXED_FILE
    mov     dword [rax + SQE_FD], ecx     ; registered backend file index
    lea     rdx, [r9 + MP_MSGHDR_OFF]
    mov     [rax + SQE_ADDR], rdx
    mov     dword [rax + SQE_OP_FLAGS], MSG_NOSIGNAL
    mov     rdx, UD_OP_SENDMSG
    mov     ecx, ebx
    or      rdx, rcx                     ; encode client_fd for diagnostics
    mov     [rax + SQE_USER_DATA], rdx

    ; --- submit close(client_fd) SQE
    call    lb_get_next_sqe
    test    rax, rax
    jz      .skip_close
    SQE_ZERO rax
    mov     byte [rax + SQE_OPCODE], IORING_OP_CLOSE
    mov     byte [rax + SQE_FLAGS], IOSQE_CQE_SKIP_SUCCESS
    mov     dword [rax + SQE_FD], ebx
    mov     rdx, UD_OP_CLOSE
    mov     ecx, ebx
    or      rdx, rcx
    mov     [rax + SQE_USER_DATA], rdx

.recheck_more:
    ; Multishot accept: kernel keeps the SQE armed and clears CQE_F_MORE only
    ; when it stops (e.g., on cancellation or fatal listen-fd error).  Re-arm
    ; only in that case; the steady state pays zero submission cost.
    test    ebp, IORING_CQE_F_MORE
    jnz     .ret
    call    arm_accept

.ret:
    add     rsp, 24
    pop     rbp
    pop     rbx
    ret

.skip_close:
    ; Fall back to a blocking close so we never leak the fd.  Should be
    ; vanishingly rare (would need ≥256 in-flight ops).
    mov     edi, ebx
    syscall0 SYS_close
    jmp     .recheck_more

; ---- lb_loop_uring -------------------------------------------------------
; Single-thread event loop.  Drains all visible CQEs, then submits +
; blocks via uring_submit_and_wait.  Never returns under normal operation.

lb_loop_uring:
    push    rbx                          ; cqe iterator
    push    rbp                          ; cq tail
    push    r12                          ; cqes base
    push    r13                          ; cq mask
    push    r14                          ; cq head ptr
    push    r15                          ; unused
    sub     rsp, 8

    call    arm_accept

.outer:
    mov     r14, [g_ring + URING_CQ_HEAD]
    mov     ebx, [r14]
    mov     rax, [g_ring + URING_CQ_TAIL]
    mov     ebp, [rax]
    cmp     ebx, ebp
    je      .submit_wait

    mov     r12, [g_ring + URING_CQES]
    mov     r13d, [g_ring + URING_CQ_MASK]

.cqe_loop:
    cmp     ebx, ebp
    je      .drained

    mov     eax, ebx
    and     eax, r13d
    shl     eax, CQE_SHIFT
    lea     rcx, [r12 + rax]

    mov     rax, [rcx + CQE_USER_DATA]
    mov     esi, [rcx + CQE_RES]
    mov     r8d, [rcx + CQE_FLAGS]
    mov     edi, eax                      ; arg1: fd (low 32) — for handlers
    shr     rax, 32                       ; op

    cmp     eax, UD_OP_ACCEPT >> UD_OP_SHIFT
    je      .h_accept
    ; UD_OP_SENDMSG / UD_OP_CLOSE only fire on errors (we set CQE_SKIP_SUCCESS).
    ; Just drop them — we already submitted both ops together so a missing
    ; close is recoverable at the kernel level (the fd gets closed on process
    ; exit if it ever leaks, which it won't in practice).
    jmp     .next

.h_accept:
    ; For accept, cqe.res IS the new client fd.  Override rdi with res.
    mov     edi, esi
    call    handle_accept_cqe

.next:
    inc     ebx
    jmp     .cqe_loop

.drained:
    mov     [r14], ebx

.submit_wait:
    lea     rdi, [g_ring]
    mov     esi, 1
    call    uring_submit_and_wait
    jmp     .outer

; ---- self_warm_child ------------------------------------------------------
; Runs only in the child of spawn_self_warm.  Opens N short TCP connections
; to localhost:<port> (i.e. back at the LB's own listening socket), sends a
; canonical POST body, drains the response, closes.  This forces the kernel
; to materialise:
;   - docker-proxy's userland forwarding fast-path (the long pole at p99);
;   - the bridge network's NAT/conntrack entry;
;   - tcp_v4_connect / inet_csk_accept / tcp_close internals;
;   - our own accept_loop + send_fd + sendmsg(SCM_RIGHTS);
;   - the API's recv_client_fds + recvfrom + parse + search + sendto.
; All of that runs once cold here so k6's first real request hits a warm
; bus.  Child terminates with exit_group(0); kernel reaps it as zombie
; (negligible at one process) until LB exits.
;
;   rdi = port (host order)

%define SELF_WARM_ITERS 32

self_warm_child:
    push    rbx                          ; iteration counter
    push    rbp                          ; port (host order)
    push    r12                          ; current fd
    sub     rsp, 4112                    ; sockaddr_in (16) + recv scratch (4096)

    mov     ebp, edi
    xor     ebx, ebx
.loop:
    cmp     ebx, SELF_WARM_ITERS
    jge     .done

    ; fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0)
    mov     edi, AF_INET
    mov     esi, SOCK_STREAM | SOCK_CLOEXEC
    xor     edx, edx
    syscall0 SYS_socket
    test    rax, rax
    js      .next                        ; transient: skip this iter
    mov     r12, rax

    ; sockaddr_in { AF_INET, htons(port), 127.0.0.1, 0 } at [rsp]
    pxor    xmm0, xmm0
    movdqu  [rsp + 0], xmm0
    mov     word [rsp + 0], AF_INET
    mov     edx, ebp
    rol     dx, 8
    mov     [rsp + 2], dx
    mov     dword [rsp + 4], 0x0100007F  ; 127.0.0.1 (network order)

    ; connect(fd, &addr, 16)
    mov     edi, r12d
    lea     rsi, [rsp + 0]
    mov     edx, 16
    syscall0 SYS_connect
    test    rax, rax
    js      .close_fd

    ; send(fd, warm_http_req, warm_http_len, MSG_NOSIGNAL)
    mov     edi, r12d
    lea     rsi, [warm_http_req]
    mov     edx, warm_http_len
    mov     r10d, MSG_NOSIGNAL
    xor     r8, r8
    xor     r9, r9
    syscall0 SYS_sendto

    ; recv(fd, scratch, 4096, 0) — blocks until response arrives; we don't
    ; inspect the bytes (the round-trip is what we wanted).
    mov     edi, r12d
    lea     rsi, [rsp + 16]
    mov     edx, 4096
    xor     r10d, r10d
    xor     r8, r8
    xor     r9, r9
    syscall0 SYS_recvfrom

.close_fd:
    mov     edi, r12d
    syscall0 SYS_close

.next:
    inc     ebx
    jmp     .loop

.done:
    xor     edi, edi
    syscall0 SYS_exit_group              ; no return; kernel collects zombie

; ---- spawn_self_warm ------------------------------------------------------
; fork() → child runs self_warm_child(port) and exits; parent returns to its
; main accept loop immediately.  The child's TCP connects land in the listen
; queue (we already listen(4096)) so even if it races ahead of the parent's
; first epoll_wait the kernel queues them safely.  Fork failure is non-fatal
; — we simply skip warm-up and start serving real traffic.
;
;   rdi = port (host order)

spawn_self_warm:
    push    rbx
    sub     rsp, 8                       ; rsp now 0 mod 16
    mov     ebx, edi

    syscall0 SYS_fork
    test    rax, rax
    js      .parent                      ; fork failed → continue without warm
    jnz     .parent                      ; pid > 0 → parent

    ; child
    mov     edi, ebx
    call    self_warm_child
    ; self_warm_child ends in exit_group; control never returns here.
    xor     edi, edi
    syscall0 SYS_exit_group

.parent:
    add     rsp, 8
    pop     rbx
    ret

; ---- _start --------------------------------------------------------------

global _start
_start:
    mov     r12, [rsp]                   ; argc
    cmp     r12, 3
    jl      .usage

    ; Tighten this process's timer slack (default 50 µs → 1 ns).  No cap.
    mov     edi, PR_SET_TIMERSLACK
    mov     esi, 1
    xor     edx, edx
    xor     r10, r10
    xor     r8, r8
    syscall0 SYS_prctl

    ; mlockall best-effort (needs IPC_LOCK or RLIMIT_MEMLOCK raised).
    mov     edi, MCL_CURRENT | MCL_FUTURE
    syscall0 SYS_mlockall

    ; port = atoi(argv[1])
    mov     rdi, [rsp + 16]
    call    atoi
    mov     r13d, eax                    ; port

    ; backend_count = min(argc-2, MAX_BACKENDS)   (argc >= 3 was checked above)
    mov     eax, r12d
    sub     eax, 2
    mov     edx, MAX_BACKENDS
    cmp     eax, edx
    cmovg   eax, edx
    mov     [backend_count], eax
    mov     r14d, eax

    ; Copy argv[2 + i] into backend_paths[i].
    ; argv[k] sits at [rsp + (k+1)*8]  (argv[0] at rsp+8, argc at rsp+0).
    xor     ecx, ecx
.cp_paths:
    cmp     ecx, r14d
    jge     .paths_done
    mov     edx, ecx
    add     edx, 2                        ; k = i + 2
    mov     rax, [rsp + rdx*8 + 8]        ; argv[k] = *(rsp + 8 + k*8)
    mov     [backend_paths + rcx*8], rax
    inc     ecx
    jmp     .cp_paths
.paths_done:

    ; tcp = listen_tcp(port)
    mov     edi, r13d
    call    listen_tcp
    test    eax, eax
    js      .fail_listen
    mov     [tcp_listen_fd], eax

    ; connect each backend with retries
    xor     ecx, ecx
.cb_loop:
    cmp     ecx, r14d
    jge     .cb_done
    mov     r15d, BACKEND_RETRIES
.try:
    push    rcx
    push    r15
    mov     rdi, [backend_paths + rcx*8]
    call    connect_uds
    pop     r15
    pop     rcx
    test    eax, eax
    jns     .got_fd
    dec     r15d
    jz      .fail_backend
    ; nanosleep 100 ms
    push    rcx
    push    r15
    sub     rsp, 16
    mov     qword [rsp + 0], 0
    mov     qword [rsp + 8], RETRY_SLEEP_NS
    lea     rdi, [rsp + 0]
    xor     esi, esi
    syscall0 SYS_nanosleep
    add     rsp, 16
    pop     r15
    pop     rcx
    jmp     .try
.got_fd:
    mov     [backends_fd + rcx*4], eax
    inc     ecx
    jmp     .cb_loop
.cb_done:

    ; io_uring path (multishot accept + registered files + linked
    ; sendmsg→close).
    ; SQ size 1024: each accept consumes 2 SQEs (sendmsg + close) plus the
    ; multishot accept itself.  Bursts of ~100 concurrent accepts can pile
    ; up enough in-flight ops to overflow a 256-slot ring, falling back to
    ; the synchronous-close path (lb.asm:.skip_close) which shows up as p99
    ; spikes.  1024 gives 4× headroom; SQ memory cost is trivial (~24 KB).
    lea     rdi, [g_ring]
    mov     esi, 1024
    call    uring_init
    test    eax, eax
    js      .fail_listen

    call    msgpool_init

    mov     eax, [tcp_listen_fd]
    mov     [reg_files + REG_LISTEN_IDX*4], eax
    xor     ecx, ecx
.rf_copy:
    cmp     ecx, [backend_count]
    jge     .rf_done
    mov     eax, [backends_fd + rcx*4]
    mov     [reg_files + (REG_BACKENDS_BASE + 0)*4 + rcx*4], eax
    inc     ecx
    jmp     .rf_copy
.rf_done:
    lea     rdi, [g_ring]
    lea     rsi, [reg_files]
    mov     edx, MAX_BACKENDS + 1
    call    uring_register_files
    test    eax, eax
    js      .fail_listen

    ; Kernel busy-poll NAPI on the ring (50 µs budget).  Best-effort.
    lea     rdi, [g_ring]
    mov     esi, 50
    call    uring_register_napi

    mov     edi, r13d
    call    spawn_self_warm

    call    lb_loop_uring

    xor     edi, edi
    syscall0 SYS_exit_group

.usage:
    mov     edi, STDERR
    lea     rsi, [usage_msg]
    mov     edx, usage_msg_len
    syscall0 SYS_write
    mov     edi, 1
    syscall0 SYS_exit_group

.fail_listen:
    mov     edi, STDERR
    lea     rsi, [err_listen_msg]
    mov     edx, err_listen_msg_len
    syscall0 SYS_write
    mov     edi, 1
    syscall0 SYS_exit_group

.fail_backend:
    mov     edi, STDERR
    lea     rsi, [err_backend_msg]
    mov     edx, err_backend_msg_len
    syscall0 SYS_write
    mov     edi, 1
    syscall0 SYS_exit_group

section .note.GNU-stack noalloc noexec nowrite progbits
