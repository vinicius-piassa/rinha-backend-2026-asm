; io_uring setup + small helper layer.  This module owns three things:
;   1. uring_init   — io_uring_setup + double mmap; populate a Ring struct
;      with cached field pointers so the hot path never re-resolves offsets.
;   2. uring_submit_and_wait — publish cached tail and call io_uring_enter
;      with IORING_ENTER_GETEVENTS so a single syscall pushes the SQ batch
;      AND blocks until ≥ wait_n CQEs are ready.
;   3. Registration helpers — uring_register_pbuf_ring, uring_register_files.
;
; The hot inner loop lives in the callers (server.asm / lb.asm); they fill
; SQEs and read CQEs inline because a function call would dominate the gain.

bits 64
default rel

%include "syscalls.inc"
%include "macros.inc"
%include "uring.inc"

section .text

; ---- uring_init -----------------------------------------------------------
; int uring_init(struct UringRing *ring, u32 sq_entries);
;   rdi = ring (output, 128 bytes)
;   esi = sq_entries (must be power of 2, ≤ 32768)
; Returns 0 OK / -1 on any error.  Caller MUST have zeroed *ring before
; calling — we don't pre-zero so the caller can decide bss/static placement.
;
; Stack: 3 push + sub 128 → rsp 0 mod 16.  Locals:
;   [rsp +   0..119]  io_uring_params
;   [rsp + 120..127]  pad

global uring_init
uring_init:
    push    rbx                          ; ring ptr
    push    r12                          ; saved entries
    push    r13                          ; saved ring_fd
    sub     rsp, 128

    mov     rbx, rdi
    mov     r12d, esi

    ; Zero io_uring_params (120 bytes; round up to 128)
    vpxor   xmm0, xmm0, xmm0
    vmovdqu [rsp + 0],   xmm0
    vmovdqu [rsp + 16],  xmm0
    vmovdqu [rsp + 32],  xmm0
    vmovdqu [rsp + 48],  xmm0
    vmovdqu [rsp + 64],  xmm0
    vmovdqu [rsp + 80],  xmm0
    vmovdqu [rsp + 96],  xmm0
    vmovdqu [rsp + 112], xmm0

    ; ring_fd = io_uring_setup(entries, &params)
    ; Graceful fallback ladder: light up low-latency flags on modern kernels
    ; but still boot on older ones.
    ;   1) SINGLE_ISSUER | DEFER_TASKRUN | SUBMIT_ALL  (Linux 6.0+)
    ;   2) COOP_TASKRUN | SUBMIT_ALL                   (Linux 5.19+)
    ;   3) 0                                           (always works)
    mov     dword [rsp + PARAMS_FLAGS], \
            IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_SUBMIT_ALL
    mov     edi, r12d
    lea     rsi, [rsp + 0]
    syscall0 SYS_io_uring_setup
    test    rax, rax
    jns     .setup_ok

    mov     dword [rsp + PARAMS_FLAGS], \
            IORING_SETUP_COOP_TASKRUN | IORING_SETUP_SUBMIT_ALL
    mov     edi, r12d
    lea     rsi, [rsp + 0]
    syscall0 SYS_io_uring_setup
    test    rax, rax
    jns     .setup_ok

    mov     dword [rsp + PARAMS_FLAGS], 0
    mov     edi, r12d
    lea     rsi, [rsp + 0]
    syscall0 SYS_io_uring_setup
    test    rax, rax
    js      .fail

.setup_ok:
    mov     r13d, eax
    mov     [rbx + URING_FD], r13d

    ; Compute SQ ring map size = sq_off.array + sq_entries * 4
    mov     ecx, [rsp + PARAMS_SQ_OFF + SQO_ARRAY]
    mov     edx, [rsp + PARAMS_SQ_ENTRIES]
    shl     edx, 2
    add     ecx, edx                     ; sq_ring bytes

    ; Compute CQ ring map size = cq_off.cqes + cq_entries * 16
    mov     eax, [rsp + PARAMS_CQ_OFF + CQO_CQES]
    mov     edx, [rsp + PARAMS_CQ_ENTRIES]
    shl     edx, CQE_SHIFT
    add     eax, edx                     ; cq_ring bytes

    ; ring_map_size = max(sq_size, cq_size).  With IORING_FEAT_SINGLE_MMAP
    ; (always present since 5.4) the SQ and CQ ring share the mapping, so
    ; one mmap covers both; the bigger of the two computed sizes is enough.
    cmp     eax, ecx
    cmovg   ecx, eax
    mov     [rbx + URING_SQ_RING_SIZE], ecx

    ; sq_ring = mmap(NULL, size, PROT_RW, MAP_SHARED|MAP_POPULATE, fd, OFF_SQ)
    xor     edi, edi
    movsxd  rsi, ecx
    mov     edx, PROT_READ | PROT_WRITE
    mov     r10d, MAP_SHARED | MAP_POPULATE
    mov     r8d, r13d
    xor     r9, r9                       ; IORING_OFF_SQ_RING == 0
    syscall0 SYS_mmap
    cmp     rax, -4096
    jae     .fail_close
    mov     [rbx + URING_SQ_RING], rax

    ; Cache pointer fields by adding sq_off.* / cq_off.* to the mmap base.
    mov     r8, rax                      ; ring base
    mov     eax, [rsp + PARAMS_SQ_OFF + SQO_HEAD]
    lea     rcx, [r8 + rax]
    mov     [rbx + URING_SQ_HEAD], rcx
    mov     eax, [rsp + PARAMS_SQ_OFF + SQO_TAIL]
    lea     rcx, [r8 + rax]
    mov     [rbx + URING_SQ_TAIL], rcx
    mov     eax, [rsp + PARAMS_SQ_OFF + SQO_FLAGS]
    lea     rcx, [r8 + rax]
    mov     [rbx + URING_SQ_FLAGS], rcx
    mov     eax, [rsp + PARAMS_SQ_OFF + SQO_ARRAY]
    lea     rcx, [r8 + rax]
    mov     [rbx + URING_SQ_ARRAY], rcx
    mov     eax, [rsp + PARAMS_SQ_OFF + SQO_RING_MASK]
    mov     ecx, [r8 + rax]              ; load the mask value
    mov     [rbx + URING_SQ_MASK], ecx

    mov     eax, [rsp + PARAMS_CQ_OFF + CQO_HEAD]
    lea     rcx, [r8 + rax]
    mov     [rbx + URING_CQ_HEAD], rcx
    mov     eax, [rsp + PARAMS_CQ_OFF + CQO_TAIL]
    lea     rcx, [r8 + rax]
    mov     [rbx + URING_CQ_TAIL], rcx
    mov     eax, [rsp + PARAMS_CQ_OFF + CQO_CQES]
    lea     rcx, [r8 + rax]
    mov     [rbx + URING_CQES], rcx
    mov     eax, [rsp + PARAMS_CQ_OFF + CQO_RING_MASK]
    mov     ecx, [r8 + rax]
    mov     [rbx + URING_CQ_MASK], ecx

    ; sqes = mmap(NULL, entries*64, PROT_RW, MAP_SHARED|POPULATE, fd, OFF_SQES)
    mov     ecx, [rsp + PARAMS_SQ_ENTRIES]
    shl     ecx, SQE_SHIFT
    mov     [rbx + URING_SQES_SIZE], ecx
    xor     edi, edi
    movsxd  rsi, ecx
    mov     edx, PROT_READ | PROT_WRITE
    mov     r10d, MAP_SHARED | MAP_POPULATE
    mov     r8d, r13d
    mov     r9d, IORING_OFF_SQES
    syscall0 SYS_mmap
    cmp     rax, -4096
    jae     .fail_unmap
    mov     [rbx + URING_SQES], rax

    ; Pre-fill the SQ indirect array (sq_array[i] = i).  We always use the
    ; trivial 1:1 mapping so the userspace tail directly indexes SQEs.
    mov     rcx, [rbx + URING_SQ_ARRAY]
    mov     edx, [rsp + PARAMS_SQ_ENTRIES]
    xor     eax, eax
.fill_arr:
    cmp     eax, edx
    jge     .arr_done
    mov     [rcx + rax*4], eax
    inc     eax
    jmp     .fill_arr
.arr_done:

    mov     dword [rbx + URING_SQ_TAIL_CACHED], 0

    ; Register the ring fd with itself so subsequent io_uring_enter calls can
    ; pass IORING_ENTER_REGISTERED_RING and a small index instead of the real
    ; fd — saves the kernel a per-call fdget/fdput.  Reuses the params slab
    ; (no longer needed) as scratch for struct io_uring_rsrc_update.
    ; On any error, fall back to using the real fd by leaving REG_FD = -1.
    mov     dword [rsp + RSRC_UPDATE_OFFSET], -1   ; let kernel assign slot
    mov     dword [rsp + RSRC_UPDATE_RESV], 0
    mov     dword [rsp + RSRC_UPDATE_DATA], r13d
    mov     dword [rsp + RSRC_UPDATE_DATA + 4], 0

    mov     edi, r13d
    mov     esi, IORING_REGISTER_RING_FDS
    lea     rdx, [rsp + 0]
    mov     r10d, 1
    syscall0 SYS_io_uring_register
    cmp     rax, 1
    jne     .reg_fd_fail
    mov     eax, [rsp + RSRC_UPDATE_OFFSET]
    mov     [rbx + URING_REG_FD], eax
    jmp     .reg_fd_done
.reg_fd_fail:
    mov     dword [rbx + URING_REG_FD], -1
.reg_fd_done:

    xor     eax, eax
    add     rsp, 128
    pop     r13
    pop     r12
    pop     rbx
    ret

.fail_unmap:
    push    rax                          ; preserve -errno across cleanup
    mov     rdi, [rbx + URING_SQ_RING]
    mov     esi, [rbx + URING_SQ_RING_SIZE]
    syscall0 SYS_munmap
    pop     rax
.fail_close:
    push    rax
    mov     edi, r13d
    syscall0 SYS_close
    pop     rax
.fail:
    add     rsp, 128
    pop     r13
    pop     r12
    pop     rbx
    ret

; ---- uring_submit_and_wait ------------------------------------------------
; int uring_submit_and_wait(Ring *ring, u32 wait_n);
;   rdi = ring, esi = min CQEs to wait for (0 = non-blocking submit only)
;
; Publishes the cached SQ tail and calls io_uring_enter with GETEVENTS so a
; single syscall handles submit+wait.  Returns the kernel's submit count
; (positive) or -errno on failure.

global uring_submit_and_wait
uring_submit_and_wait:
    push    rbx
    push    r12
    sub     rsp, 8                       ; rsp 0 mod 16

    mov     rbx, rdi
    mov     r12d, esi

    ; Publish cached tail.  On x86-64, store-release is just a plain mov;
    ; kernel will see it before reading SQ entries because syscall provides
    ; the necessary barrier.
    mov     rcx, [rbx + URING_SQ_TAIL]
    mov     edx, [rbx + URING_SQ_TAIL_CACHED]
    mov     [rcx], edx

    ; submit_count = cached_tail - kernel_head (mod 2^32; cheaper as i32 sub)
    mov     rcx, [rbx + URING_SQ_HEAD]
    mov     eax, [rcx]
    mov     ecx, edx
    sub     ecx, eax                     ; submit count

    ; Pick arg1 (ring identifier) + enter flags: prefer the registered ring
    ; index when uring_init managed to install one, falling back to the real
    ; ring fd otherwise.  Computed before the syscall arg moves so edx (which
    ; gets overwritten with min_complete below) is free to scratch.
    mov     eax, [rbx + URING_REG_FD]
    mov     edi, [rbx + URING_FD]            ; default: real ring fd
    test    eax, eax
    js      .use_real_fd
    mov     edi, eax                          ; registered index
    mov     r10d, IORING_ENTER_GETEVENTS | IORING_ENTER_REGISTERED_RING
    jmp     .do_enter
.use_real_fd:
    mov     r10d, IORING_ENTER_GETEVENTS

.do_enter:
    ; io_uring_enter(ring_or_idx, to_submit, min_complete, flags, NULL, 0)
    mov     esi, ecx
    mov     edx, r12d
    xor     r8, r8
    xor     r9, r9
    syscall0 SYS_io_uring_enter

    add     rsp, 8
    pop     r12
    pop     rbx
    ret

; ---- uring_submit_no_wait -------------------------------------------------
; void uring_submit_no_wait(Ring *ring);
;   rdi = ring
;
; Publishes the cached SQ tail and calls io_uring_enter WITHOUT GETEVENTS
; (min_complete = 0).  Kicks the kernel into processing queued SQEs while
; userspace continues to busy-poll for completions.  Never blocks.

global uring_submit_no_wait
uring_submit_no_wait:
    push    rbx
    sub     rsp, 8

    mov     rbx, rdi

    ; Publish cached tail (plain store; syscall provides the barrier).
    mov     rcx, [rbx + URING_SQ_TAIL]
    mov     edx, [rbx + URING_SQ_TAIL_CACHED]
    mov     [rcx], edx

    ; submit_count = cached_tail - kernel_head
    mov     rcx, [rbx + URING_SQ_HEAD]
    mov     eax, [rcx]
    mov     ecx, edx
    sub     ecx, eax
    jz      .done                        ; nothing to submit — skip the syscall

    ; Pick fd / flag using the same registered-ring trick as submit_and_wait.
    mov     eax, [rbx + URING_REG_FD]
    mov     edi, [rbx + URING_FD]
    test    eax, eax
    js      .use_real_fd
    mov     edi, eax
    mov     r10d, IORING_ENTER_REGISTERED_RING
    jmp     .do_enter
.use_real_fd:
    xor     r10d, r10d                   ; no flags = non-blocking submit
.do_enter:
    mov     esi, ecx                     ; submit_count
    xor     edx, edx                     ; min_complete = 0
    xor     r8, r8
    xor     r9, r9
    syscall0 SYS_io_uring_enter

.done:
    add     rsp, 8
    pop     rbx
    ret

; ---- uring_register_pbuf_ring ---------------------------------------------
; int uring_register_pbuf_ring(Ring *ring, void *buf_ring_mem, u32 entries,
;                              u16 bgid);
;   Registers a provided-buffer ring (kernel-side, IORING_REGISTER_PBUF_RING).
;   Returns 0 OK / -errno.

global uring_register_pbuf_ring
uring_register_pbuf_ring:
    push    rbx
    sub     rsp, 48                       ; struct io_uring_buf_reg (40) + pad

    mov     rbx, rdi

    vpxor   xmm0, xmm0, xmm0
    vmovdqu [rsp + 0],  xmm0
    vmovdqu [rsp + 16], xmm0
    movdqu  [rsp + 32], xmm0              ; covers 32..47

    mov     [rsp + BUF_REG_RING_ADDR], rsi
    mov     [rsp + BUF_REG_RING_ENTRIES], edx
    mov     [rsp + BUF_REG_BGID], cx

    ; io_uring_register(ring_fd, REGISTER_PBUF_RING, &reg, 1)
    mov     edi, [rbx + URING_FD]
    mov     esi, IORING_REGISTER_PBUF_RING
    lea     rdx, [rsp + 0]
    mov     r10d, 1
    syscall0 SYS_io_uring_register

    add     rsp, 48
    pop     rbx
    ret

; ---- uring_register_files -------------------------------------------------
; int uring_register_files(Ring *ring, int *fds, u32 nr_fds);
;   Registers an array of fds with the ring so SQEs can reference them by
;   index (with IOSQE_FIXED_FILE).  Returns 0 OK / -errno.

global uring_register_files
uring_register_files:
    push    rbx
    mov     rbx, rdi

    ; Stash args because the syscall arg layout shifts rdi/rsi/rdx/r10.
    mov     r8, rsi                      ; fds ptr (caller arg2)
    mov     r9d, edx                     ; nr_fds (caller arg3)

    mov     edi, [rbx + URING_FD]
    mov     esi, IORING_REGISTER_FILES
    mov     rdx, r8
    mov     r10d, r9d
    syscall0 SYS_io_uring_register

    pop     rbx
    ret

; ---- uring_register_napi --------------------------------------------------
; void uring_register_napi(Ring *ring, u32 busy_poll_us);
;
; Tells the kernel to busy-poll the socket's NAPI handler for `busy_poll_us`
; microseconds inside io_uring_enter before sleeping.  Cuts the NIC→user
; wake-up latency at the cost of a bit of kernel CPU.  Best-effort: kernels
; older than 6.9 return -EINVAL and we silently ignore.

global uring_register_napi
uring_register_napi:
    push    rbx
    sub     rsp, 24                       ; struct io_uring_napi (20 B) + align

    mov     rbx, rdi

    ; Zero all 24 bytes (covers the 20-byte struct + slack).  Kernel ≥6.9
    ; checks resv[3] is fully zero; even one uninitialised byte → -EINVAL.
    xor     eax, eax
    mov     [rsp + 0],  rax
    mov     [rsp + 8],  rax
    mov     [rsp + 16], rax
    mov     [rsp + NAPI_BUSY_POLL_TO], esi
    mov     byte [rsp + NAPI_PREFER_BUSY_POLL], 1

    mov     edi, [rbx + URING_FD]
    mov     esi, IORING_REGISTER_NAPI
    lea     rdx, [rsp + 0]
    mov     r10d, 1
    syscall0 SYS_io_uring_register
    ; Ignore return value — best-effort on kernels that don't support it.

    add     rsp, 24
    pop     rbx
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
