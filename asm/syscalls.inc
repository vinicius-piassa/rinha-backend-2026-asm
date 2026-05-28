; Linux x86-64 syscall numbers and macros.
;
; Calling convention for syscall:
;   rax = syscall number
;   args: rdi, rsi, rdx, r10, r8, r9   (NOTE: r10, not rcx — the syscall
;                                       instruction clobbers rcx/r11)
;   ret: rax  (negative on error, value is -errno)
;
; Reference: linux/arch/x86/entry/syscalls/syscall_64.tbl
;
%ifndef SYSCALLS_INC
%define SYSCALLS_INC

%define SYS_read              0
%define SYS_write             1
%define SYS_open              2
%define SYS_close             3
%define SYS_fstat             5
%define SYS_lseek             8
%define SYS_mmap              9
%define SYS_mprotect          10
%define SYS_munmap            11
%define SYS_brk               12
%define SYS_rt_sigaction      13
%define SYS_rt_sigprocmask    14
%define SYS_ioctl             16
%define SYS_pread64           17
%define SYS_pwrite64          18
%define SYS_readv             19
%define SYS_writev            20
%define SYS_madvise           28
%define SYS_dup               32
%define SYS_dup2              33
%define SYS_nanosleep         35
%define SYS_getpid            39
%define SYS_sendfile          40
%define SYS_socket            41
%define SYS_connect           42
%define SYS_accept            43
%define SYS_sendto            44
%define SYS_recvfrom          45
%define SYS_sendmsg           46
%define SYS_recvmsg           47
%define SYS_shutdown          48
%define SYS_bind              49
%define SYS_listen            50
%define SYS_setsockopt        54
%define SYS_getsockopt        55
%define SYS_clone             56
%define SYS_fork              57
%define SYS_execve            59
%define SYS_exit              60
%define SYS_wait4             61
%define SYS_kill              62
%define SYS_uname             63
%define SYS_fcntl             72
%define SYS_unlink            87
%define SYS_chmod             90
%define SYS_mlock             149
%define SYS_munlock           150
%define SYS_mlockall          151
%define SYS_arch_prctl        158
%define SYS_prctl             157
%define PR_SET_TIMERSLACK     29
%define SYS_setrlimit         160
%define SYS_sched_setparam    142
%define SYS_sched_getparam    143
%define SYS_sched_setscheduler 144
%define SYS_sched_setaffinity 203
%define SYS_sched_getaffinity 204
%define SYS_clock_gettime     228
%define SYS_clock_nanosleep   230
%define SYS_exit_group        231
%define SYS_epoll_create1     291
%define SYS_epoll_ctl         233
%define SYS_epoll_wait        232
%define SYS_epoll_pwait       281
%define SYS_accept4           288
%define SYS_eventfd2          290
%define SYS_pipe2             293
%define SYS_io_uring_setup    425
%define SYS_io_uring_enter    426
%define SYS_io_uring_register 427

; ---------------------------------------------------------------------------
; sys0..sys6 macros — invoke syscall with N args, return value in rax.
; Caller is responsible for spilling rcx/r11 if those matter (rare).
;
; Args before macro:
;   rdi, rsi, rdx, r10, r8, r9 hold args 1..6 in System V order, EXCEPT
;   that the 4th arg goes in r10 (the kernel's choice). Caller must move
;   rcx -> r10 before invoking sys4+ macros if coming from a SysV call.
; ---------------------------------------------------------------------------

%macro syscall0 1
    mov     eax, %1
    syscall
%endmacro

%macro syscall1 1
    mov     eax, %1
    syscall
%endmacro

%macro syscall2 1
    mov     eax, %1
    syscall
%endmacro

%macro syscall3 1
    mov     eax, %1
    syscall
%endmacro

; sys4+: caller must already have arg4 in r10 (NOT rcx).
%macro syscall4 1
    mov     eax, %1
    syscall
%endmacro

%macro syscall5 1
    mov     eax, %1
    syscall
%endmacro

%macro syscall6 1
    mov     eax, %1
    syscall
%endmacro

; ---------------------------------------------------------------------------
; Common constants
; ---------------------------------------------------------------------------

%define AF_INET               2
%define AF_UNIX               1
%define SOCK_STREAM           1
%define SOCK_CLOEXEC          0x80000
%define SOCK_NONBLOCK         0x800
%define SOL_SOCKET            1
%define SO_REUSEADDR          2
%define SO_SNDTIMEO           21
%define SO_RCVTIMEO           20
%define SO_REUSEPORT          15
%define SO_INCOMING_CPU       49
%define SO_BUSY_POLL          46
%define SO_PREFER_BUSY_POLL   69       ; Linux 5.7+ — prefer NAPI busy poll
%define SO_BUSY_POLL_BUDGET   70       ; Linux 5.7+ — packet budget per call
%define TCP_DEFER_ACCEPT      9
%define TCP_NOTSENT_LOWAT     25
%define TCP_FASTOPEN          23       ; Linux 3.7+ — server-side accept queue
%define SOL_TCP               6
%define TCP_NODELAY           1
%define TCP_QUICKACK          12
%define MSG_NOSIGNAL          0x4000
%define MSG_PEEK              0x0002
%define MSG_DONTWAIT          0x0040
%define MSG_CMSG_CLOEXEC      0x40000000
%define SCM_RIGHTS            1

%define EPOLLIN               0x001
%define EPOLLOUT              0x004
%define EPOLLERR              0x008
%define EPOLLHUP              0x010
%define EPOLLRDHUP            0x2000
%define EPOLLET               0x80000000
%define EPOLL_CTL_ADD         1
%define EPOLL_CTL_DEL         2
%define EPOLL_CTL_MOD         3
%define EPOLL_CLOEXEC         0x80000

; EPIOCSPARAMS — set epoll busy-poll parameters (Linux 6.9+).
; _IOW('p', 0x01, sizeof(struct epoll_params)=8):
;   (1<<30) | (8<<16) | ('p'<<8) | 0x01 = 0x40087001.
; Struct layout (8 bytes):
;   u32 busy_poll_usecs   — microseconds the kernel busy-polls inside epoll_wait
;   u16 busy_poll_budget  — max NAPI poll packets per call
;   u8  prefer_busy_poll  — 1 to prefer busy poll over standard sleep
;   u8  __pad
%define EPIOCSPARAMS          0x40087001

%define PROT_READ             1
%define PROT_WRITE            2
%define MAP_SHARED            0x01
%define MAP_PRIVATE           0x02
%define MAP_FIXED             0x10
%define MAP_ANONYMOUS         0x20
%define MAP_POPULATE          0x8000
%define MAP_HUGETLB           0x40000

%define MADV_WILLNEED         3
%define MADV_HUGEPAGE         14

%define MCL_CURRENT           1
%define MCL_FUTURE            2

%define SCHED_OTHER           0
%define SCHED_FIFO            1
%define SCHED_RR              2

%define WORKER_RT_PRIO        10

%define O_RDONLY              0
%define O_WRONLY              1
%define O_RDWR                2
%define O_CREAT               0x40
%define O_TRUNC               0x200
%define O_NONBLOCK            0x800
%define O_CLOEXEC             0x80000

%define F_GETFL               3
%define F_SETFL               4

%define EAGAIN                11
%define EINTR                 4
%define EINPROGRESS           115

%define STDIN                 0
%define STDOUT                1
%define STDERR                2

%endif ; SYSCALLS_INC
