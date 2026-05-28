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

%define MAX_BACKENDS    8
%define MAX_EVENTS      128
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

; epoll_params struct for EPIOCSPARAMS ioctl (Linux 6.9+).  Same rationale
; as in server.asm: turns our spin-on-epoll_wait(0) into a single syscall
; whose internal NAPI busy-poll loop catches incoming connections in <50µs.
align 8
epoll_busy_params:
    dd 50                                 ; busy_poll_usecs
    dw 8                                  ; busy_poll_budget
    db 1                                  ; prefer_busy_poll
    db 0                                  ; __pad

; ===========================================================================
section .bss
alignb 8
backends_fd:    resd MAX_BACKENDS
backend_paths:  resq MAX_BACKENDS
backend_count:  resd 1
rr_cursor:      resd 1
tcp_listen_fd:  resd 1
epoll_fd:       resd 1
alignb 16
events_buf:     resb MAX_EVENTS * EPOLL_EV_SIZE

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

    ; SO_BUSY_POLL — per-socket NAPI busy-poll usecs.  Complements the
    ; EPIOCSPARAMS we set on the epoll; this one applies to socket-level
    ; ops (the accept_loop's accept4 path).  Best-effort.
    mov     dword [rsp + 16], 50
    mov     edi, ebx
    mov     esi, SOL_SOCKET
    mov     edx, SO_BUSY_POLL
    lea     r10, [rsp + 16]
    mov     r8d, 4
    syscall0 SYS_setsockopt

    ; SO_PREFER_BUSY_POLL = 1 (Linux 5.7+).  Tells the kernel to favour the
    ; busy-poll path over interrupt-driven wake.
    mov     dword [rsp + 16], 1
    mov     edi, ebx
    mov     esi, SOL_SOCKET
    mov     edx, SO_PREFER_BUSY_POLL
    lea     r10, [rsp + 16]
    mov     r8d, 4
    syscall0 SYS_setsockopt

    ; SO_BUSY_POLL_BUDGET = 8 (Linux 5.7+).  Max packets handled per
    ; busy-poll round; mirrors the EPIOCSPARAMS budget.
    mov     dword [rsp + 16], 8
    mov     edi, ebx
    mov     esi, SOL_SOCKET
    mov     edx, SO_BUSY_POLL_BUDGET
    lea     r10, [rsp + 16]
    mov     r8d, 4
    syscall0 SYS_setsockopt

    ; TCP_FASTOPEN = 256 (server-side TFO queue length).  Lets clients
    ; that support TFO skip the initial RTT by stuffing payload into the
    ; SYN.  k6 may or may not enable client-side TFO — best-effort.
    mov     dword [rsp + 16], 256
    mov     edi, ebx
    mov     esi, SOL_TCP
    mov     edx, TCP_FASTOPEN
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

    ; (Previously: setsockopt(TCP_NODELAY) + setsockopt(TCP_QUICKACK) per
    ;  accept.  Both are no-ops in our req/resp pattern: response always
    ;  piggybacks the ACK of the inbound POST, so server-side has no
    ;  unACKed segments when sending — Nagle never engages, delayed-ACK
    ;  never fires standalone.  Removing the two setsockopt syscalls
    ;  saves ~50ns/req amortised over keep-alive.)

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

; The LB stays on a blocking epoll_wait — its 0.05 cpu cap (5% of one
; core) can't afford the userspace busy-poll spin that the APIs use.
; A 50 µs spin window × 5k accept events/sec would consume ~27% CPU and
; trigger CFS throttling that backs up the accept queue.

server_loop:
    push    rbx                          ; n events (callee-save)
    push    r12                          ; ev iter index (callee-save — survives
                                         ; syscalls inside accept_loop that clobber rcx)
                                         ; 2 pushes → rsp 0 mod 16 ✓

.outer:
    mov     edi, [epoll_fd]
    lea     rsi, [events_buf]
    mov     edx, MAX_EVENTS
    mov     r10d, -1
    syscall0 SYS_epoll_wait
    test    rax, rax
    js      .check_eintr

    mov     ebx, eax
    xor     r12d, r12d
.ev_loop:
    cmp     r12d, ebx
    jge     .outer

    movsxd  rax, r12d
    imul    rax, rax, EPOLL_EV_SIZE
    lea     rdx, [events_buf]
    mov     edi, [rdx + rax + EPOLL_EV_FD]

    cmp     edi, [tcp_listen_fd]
    jne     .next
    call    accept_loop

.next:
    inc     r12d
    jmp     .ev_loop

.check_eintr:
    cmp     rax, -EINTR
    je      .outer
    pop     r12
    pop     rbx
    ret


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

    ; epoll path: single-thread event loop driving accept4 → send_fd → close.
    ;   1) epoll_create1(EPOLL_CLOEXEC)
    ;   2) epoll_ctl(ADD, tcp_listen_fd, EPOLLIN | EPOLLET)
    ;      Edge-triggered + nonblocking listen socket → accept_loop drains
    ;      until EAGAIN every wake-up.  No multishot accept here (would need
    ;      io_uring); the cost is one extra epoll_wait return per burst.
    mov     edi, EPOLL_CLOEXEC
    syscall0 SYS_epoll_create1
    test    eax, eax
    js      .fail_listen
    mov     [epoll_fd], eax

    ; ioctl(epfd, EPIOCSPARAMS, &epoll_busy_params)  [Linux 6.9+, best-effort].
    mov     edi, [epoll_fd]
    mov     esi, EPIOCSPARAMS
    lea     rdx, [epoll_busy_params]
    syscall0 SYS_ioctl

    sub     rsp, 16
    mov     dword [rsp + 0], EPOLLIN | EPOLLET
    mov     eax, [tcp_listen_fd]
    mov     [rsp + 4], eax                ; data.fd at offset 4 of epoll_event
    mov     edi, [epoll_fd]
    mov     esi, EPOLL_CTL_ADD
    mov     edx, eax
    lea     r10, [rsp + 0]
    syscall0 SYS_epoll_ctl
    add     rsp, 16
    test    eax, eax
    js      .fail_listen

    mov     edi, r13d
    call    spawn_self_warm

    call    server_loop

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
