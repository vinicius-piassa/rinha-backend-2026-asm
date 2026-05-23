; io_uring ABI constants — struct offsets, opcodes, flags.
;
; Reference: include/uapi/linux/io_uring.h (Linux 6.17).  We pin to a small,
; stable subset that works on every kernel ≥ 5.19, plus the buffer-ring
; protocol introduced in 5.19 (IORING_REGISTER_PBUF_RING).
;
; Layout notes:
;   - io_uring_sqe is 64 bytes; entries 0..63 must be exactly aligned.
;   - io_uring_cqe is 16 bytes by default (32 with IORING_SETUP_CQE32, which
;     we do NOT use).
;   - io_uring_params is 120 bytes.

%ifndef URING_INC
%define URING_INC

; ===========================================================================
; struct io_uring_sqe — 64 bytes
; ===========================================================================
%define SQE_OPCODE              0    ; u8
%define SQE_FLAGS               1    ; u8
%define SQE_IOPRIO              2    ; u16
%define SQE_FD                  4    ; s32
%define SQE_OFF                 8    ; u64 (union: off / addr2 / cmd_op)
%define SQE_ADDR                16   ; u64 (union: addr / level+optname)
%define SQE_LEN                 24   ; u32
%define SQE_OP_FLAGS            28   ; u32 (union: msg_flags / accept_flags / ...)
%define SQE_USER_DATA           32   ; u64
%define SQE_BUF_GROUP           40   ; u16 (union with buf_index)
%define SQE_PERSONALITY         42   ; u16
%define SQE_FILE_INDEX          44   ; s32 (union: splice_fd_in / file_index)
%define SQE_ADDR3               48   ; u64 (union: optval)
%define SQE_PAD2                56   ; u64

%define SQE_SIZE                64
%define SQE_SHIFT               6    ; log2(64), for shl in array indexing

; ===========================================================================
; struct io_uring_cqe — 16 bytes
; ===========================================================================
%define CQE_USER_DATA           0    ; u64
%define CQE_RES                 8    ; s32
%define CQE_FLAGS               12   ; u32

%define CQE_SIZE                16
%define CQE_SHIFT               4    ; log2(16)

; CQE flags
%define IORING_CQE_F_BUFFER     0x1   ; buffer index in high 16 bits of flags
%define IORING_CQE_F_MORE       0x2   ; more completions coming for this user_data
%define IORING_CQE_F_SOCK_NONEMPTY 0x4
%define IORING_CQE_F_NOTIF      0x8

%define IORING_CQE_BUFFER_SHIFT 16    ; flags >> 16 = buffer id

; ===========================================================================
; struct io_uring_params — 120 bytes
; ===========================================================================
%define PARAMS_SQ_ENTRIES       0    ; u32
%define PARAMS_CQ_ENTRIES       4    ; u32
%define PARAMS_FLAGS            8    ; u32
%define PARAMS_SQ_THREAD_CPU    12   ; u32
%define PARAMS_SQ_THREAD_IDLE   16   ; u32
%define PARAMS_FEATURES         20   ; u32
%define PARAMS_WQ_FD            24   ; u32
%define PARAMS_RESV             28   ; u32[3] — 12 bytes
%define PARAMS_SQ_OFF           40   ; io_sqring_offsets (40 bytes)
%define PARAMS_CQ_OFF           80   ; io_cqring_offsets (40 bytes)
%define PARAMS_SIZE             120

; struct io_sqring_offsets at PARAMS_SQ_OFF (40 bytes)
%define SQO_HEAD                0    ; u32 — kernel-side head
%define SQO_TAIL                4    ; u32 — userspace-side tail (we advance)
%define SQO_RING_MASK           8    ; u32
%define SQO_RING_ENTRIES        12   ; u32
%define SQO_FLAGS               16   ; u32 — IORING_SQ_NEED_WAKEUP etc.
%define SQO_DROPPED             20   ; u32
%define SQO_ARRAY               24   ; u32 — offset to indirect SQE-index array
%define SQO_RESV1               28
%define SQO_USER_ADDR           32   ; u64

; struct io_cqring_offsets at PARAMS_CQ_OFF (40 bytes, same shape as SQ minus array)
%define CQO_HEAD                0
%define CQO_TAIL                4
%define CQO_RING_MASK           8
%define CQO_RING_ENTRIES        12
%define CQO_OVERFLOW            16
%define CQO_CQES                20   ; u32 — offset to CQE array
%define CQO_FLAGS               24
%define CQO_RESV1               28
%define CQO_USER_ADDR           32

; ===========================================================================
; io_uring opcodes (we only declare the ones we use)
; ===========================================================================
%define IORING_OP_NOP            0
%define IORING_OP_READV          1
%define IORING_OP_WRITEV         2
%define IORING_OP_FSYNC          3
%define IORING_OP_READ_FIXED     4
%define IORING_OP_WRITE_FIXED    5
%define IORING_OP_POLL_ADD       6
%define IORING_OP_POLL_REMOVE    7
%define IORING_OP_SENDMSG        9
%define IORING_OP_RECVMSG        10
%define IORING_OP_TIMEOUT        11
%define IORING_OP_ACCEPT         13
%define IORING_OP_ASYNC_CANCEL   14
%define IORING_OP_CONNECT        16
%define IORING_OP_CLOSE          19
%define IORING_OP_READ           22
%define IORING_OP_WRITE          23
%define IORING_OP_SEND           26
%define IORING_OP_RECV           27
%define IORING_OP_SHUTDOWN       34

; ===========================================================================
; SQE flags (per-entry)
; ===========================================================================
%define IOSQE_FIXED_FILE        (1 << 0)   ; fd is an index into registered files
%define IOSQE_IO_DRAIN          (1 << 1)
%define IOSQE_IO_LINK           (1 << 2)   ; link to next SQE (success-only chain)
%define IOSQE_IO_HARDLINK       (1 << 3)
%define IOSQE_ASYNC             (1 << 4)
%define IOSQE_BUFFER_SELECT     (1 << 5)   ; kernel picks buffer from group
%define IOSQE_CQE_SKIP_SUCCESS  (1 << 6)

; ===========================================================================
; io_uring_setup flags
; ===========================================================================
%define IORING_SETUP_SQPOLL        (1 << 1)
%define IORING_SETUP_CQSIZE        (1 << 3)
%define IORING_SETUP_CLAMP         (1 << 4)
%define IORING_SETUP_SINGLE_ISSUER (1 << 12)
%define IORING_SETUP_COOP_TASKRUN  (1 << 8)
%define IORING_SETUP_DEFER_TASKRUN (1 << 13)

; ===========================================================================
; io_uring_enter flags
; ===========================================================================
%define IORING_ENTER_GETEVENTS     (1 << 0)
%define IORING_ENTER_SQ_WAKEUP     (1 << 1)
%define IORING_ENTER_SQ_WAIT       (1 << 2)
%define IORING_ENTER_EXT_ARG       (1 << 3)

; ===========================================================================
; io_uring_register opcodes
; ===========================================================================
%define IORING_REGISTER_BUFFERS    0
%define IORING_UNREGISTER_BUFFERS  1
%define IORING_REGISTER_FILES      2
%define IORING_UNREGISTER_FILES    3
%define IORING_REGISTER_PBUF_RING  22   ; provided buffer ring
%define IORING_UNREGISTER_PBUF_RING 23

; ===========================================================================
; Provided-buffer-ring (IORING_REGISTER_PBUF_RING) struct io_uring_buf_reg
; ===========================================================================
%define BUF_REG_RING_ADDR       0    ; u64 — ring memory
%define BUF_REG_RING_ENTRIES    8    ; u32 — must be power of two ≤ 2^15
%define BUF_REG_BGID            12   ; u16 — buffer group id
%define BUF_REG_FLAGS           14   ; u16
%define BUF_REG_RESV            16   ; u64[3] — 24 bytes
%define BUF_REG_SIZE            40

; struct io_uring_buf — 16 bytes per entry in the buf ring.
;   addr is __u64 at offset 0..7; len at 8..11; bid at 12..13; resv at 14..15.
%define BUF_ADDR                0    ; u64
%define BUF_LEN                 8    ; u32
%define BUF_BID                 12   ; u16
%define BUF_RESV                14   ; u16
%define BUF_ENTRY_SIZE          16
%define BUF_ENTRY_SHIFT         4

; Per-spec, the first entry of the ring is the *head/tail* pair; subsequent
; (entries) slots hold actual io_uring_buf records.  Userspace publishes by
; writing tail; kernel reads head.

; ===========================================================================
; SQ ring `flags` field bits
; ===========================================================================
%define IORING_SQ_NEED_WAKEUP   (1 << 0)
%define IORING_SQ_CQ_OVERFLOW   (1 << 1)

; ===========================================================================
; mmap offsets used to map the ring memory
; ===========================================================================
%define IORING_OFF_SQ_RING      0x00000000
%define IORING_OFF_CQ_RING      0x08000000
%define IORING_OFF_SQES         0x10000000

; ===========================================================================
; ioprio-field flags (sqe->ioprio at SQE_IOPRIO=2)
; ===========================================================================
%define IORING_ACCEPT_MULTISHOT (1 << 0)
%define IORING_RECVSEND_POLL_FIRST (1 << 0)
%define IORING_RECV_MULTISHOT   (1 << 1)
%define IORING_RECVSEND_FIXED_BUF (1 << 2)

; ===========================================================================
; Our Ring struct — 128 bytes, all pointers + a few u32 caches.
; Holds everything the hot path needs about one io_uring instance, so the
; submit/poll inner loops never have to chase indirection.
; ===========================================================================
%define URING_FD                0    ; int + 4 pad
%define URING_SQ_RING           8    ; void* — mmap base of SQ ring (== CQ_RING on SINGLE_MMAP)
%define URING_SQES              16   ; struct io_uring_sqe* — mmap base of SQE array
%define URING_SQ_HEAD           24   ; u32* — kernel-side head
%define URING_SQ_TAIL           32   ; u32* — userspace-side tail
%define URING_SQ_FLAGS          40   ; u32* — IORING_SQ_NEED_WAKEUP etc.
%define URING_SQ_ARRAY          48   ; u32* — indirect SQE index array
%define URING_CQ_HEAD           56   ; u32*
%define URING_CQ_TAIL           64   ; u32*
%define URING_CQES              72   ; struct io_uring_cqe*
%define URING_SQ_MASK           80   ; u32
%define URING_CQ_MASK           84   ; u32
%define URING_SQ_RING_SIZE      88   ; u32 — bytes for munmap
%define URING_SQES_SIZE         92   ; u32
%define URING_SQ_TAIL_CACHED    96   ; u32 — local copy of tail for batching
%define URING_PAD               100  ; 28 bytes pad → 128 total
%define URING_SIZE              128

; ===========================================================================
; Helper macros — fill an SQE with a single op.  All take rdi = SQE pointer.
; Callers may chain with IOSQE_IO_LINK by ORing into the SQE_FLAGS byte
; *after* the macro.
; ===========================================================================

; SQE_ZERO  — zero the 64-byte SQE.  Uses xmm0; caller may need to spill.
%macro SQE_ZERO 1
    vpxor   xmm0, xmm0, xmm0
    vmovdqu [%1 + 0],  xmm0
    vmovdqu [%1 + 16], xmm0
    vmovdqu [%1 + 32], xmm0
    vmovdqu [%1 + 48], xmm0
%endmacro

; ===========================================================================
; user_data encoding scheme
;
; We pack op-type in the high 32 bits and fd (or context index) in the low
; 32 bits, so the dispatch in the CQE loop is a single SHR-then-cmp on rax.
; ===========================================================================
%define UD_OP_SHIFT     32
%define UD_OP_RECV      (1 << UD_OP_SHIFT)
%define UD_OP_SEND      (2 << UD_OP_SHIFT)
%define UD_OP_CLOSE     (3 << UD_OP_SHIFT)
%define UD_OP_RECVMSG   (4 << UD_OP_SHIFT)
%define UD_OP_SENDMSG   (5 << UD_OP_SHIFT)
%define UD_OP_ACCEPT    (6 << UD_OP_SHIFT)

%endif ; URING_INC
