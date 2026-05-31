; Offline index builder — pure asm port of tools/build_index.c.
;
; Pipeline:
;   1. read references.json (decompressed; gunzip runs in Makefile prereq)
;   2. parse the outer array: each element = {"vector":[14 floats],"label":"…"}
;   3. quantize to i16 (later phase)
;   4. k-means k=2048 over f32 vectors (later phase)
;   5. counting sort by cluster; per-cluster bbox; pack 7 SoA pair arrays
;   6. emit index.bin in the same byte layout `index_open` reads.
;
; This file delivers the complete pipeline:
;   9a -- parse_refs                    (JSON corpus → Ref[])
;   9b -- l2sq_f32                       (14-dim L2 via AVX2 FMA)
;   9c -- kmeans                         (init + n_iters × assign + recompute)
;   9d -- counting_sort_by_cluster +
;         bbox_pack + write_index_bin   (post-kmeans path)
;   9e -- _start                         (argv → mmap → drive everything)
;
; Ref layout (64 bytes, fits cache line):
;   [0..55]  float v[14]    -- 14-dim vector
;   [56]     uint8 label    -- 1 if "fraud" else 0
;   [57..63] padding

bits 64
default rel

%include "syscalls.inc"
%include "macros.inc"

extern skip_ws
extern parse_number
extern skip_string_body
extern skip_value

%define REF_SIZE       64
%define REF_VEC_OFF    0
%define REF_LABEL_OFF  56

; ===========================================================================
section .rodata
align 32
c_dim_mask:                          ; lanes 14,15 → 0 so they contribute nothing
    dd 0x3F800000, 0x3F800000, 0x3F800000, 0x3F800000
    dd 0x3F800000, 0x3F800000, 0x00000000, 0x00000000
align 8
c_one_d:    dq 1.0

align 32
c_scale_f32_vec:                     ; SCALE = 10000.0f broadcast across 8 lanes
    dd 0x461C4000, 0x461C4000, 0x461C4000, 0x461C4000
    dd 0x461C4000, 0x461C4000, 0x461C4000, 0x461C4000

; --- INT8 percentile-quantization constants ---
align 4
c_one_s_bi:     dd 0x3F800000        ; 1.0 f32
c_4096_s_bi:    dd 0x45800000        ; 4096.0 f32
c_neg_half_s:   dd 0xBF000000        ; -0.5 f32  (sentinel boundary)
c_upper_s:      dd 0x40000000        ; 2.0 f32   (last bucket catch-all)
c_inv_4096_s:   dd 0x39800000        ; 1.0/4096 f32 (≈ 2.44e-4)
c_inv_128_s:    dd 0x3C000000        ; 1.0/128 f32  (= 0.0078125)
c_inv_256_s:    dd 0x3B800000        ; 1.0/256 f32  (= 0.00390625)
c_inv_254_s:    dd 0x3B816A41        ; 1.0/254 f32  (≈ 0.003937, sentinel dims use 254 buckets)
c_minus_half_s: dd 0xBF000000        ; -0.5 f32  (sentinel bucket boundary)

; Per-dim observed [min, max] from references.json analysis (3M refs).  For
; sentinel dims (5, 6), min/max here are NON-SENTINEL bounds; bucket 0 of
; the threshold table is reserved separately for sentinel values.
align 16
c_dim_min:
    dd  0.001,  0.0833, 0.05,   0.0,   0.0,    0.0,    0.0,   0.0
    dd  0.05,   0.0,    0.0,    0.0,   0.15,   0.002,  0.0,   0.0  ; tail 2 = pad
align 16
c_dim_max:
    dd  1.0,    1.0,    1.0,    0.9565, 1.0,    0.4993, 1.0,   1.0
    dd  1.0,    1.0,    1.0,    1.0,    0.85,   0.05,   0.0,   0.0  ; tail 2 = pad
; Sentinel-aware flag per dim: 1 if -1 sentinel possible (dims 5, 6), else 0.
c_dim_sent:
    db  0, 0, 0, 0, 0, 1, 1, 0
    db  0, 0, 0, 0, 0, 0

err_open_in_msg:    db "build_index: failed to open input", 10
err_open_in_len  equ $ - err_open_in_msg
err_open_out_msg:   db "build_index: failed to open output", 10
err_open_out_len equ $ - err_open_out_msg
err_parse_msg:      db "build_index: JSON parse error", 10
err_parse_len    equ $ - err_parse_msg
err_mmap_msg:       db "build_index: mmap failed", 10
err_mmap_len     equ $ - err_mmap_msg
usage_bi_msg:       db "usage: asm_build_index <input.json> <output.bin>", 10
usage_bi_len     equ $ - usage_bi_msg
done_msg:           db "build_index: done", 10
done_len         equ $ - done_msg

; ===========================================================================
section .text

; ---- parse_refs ----------------------------------------------------------
; ssize_t parse_refs(const char *buf, size_t len,
;                    void *refs_out, size_t max_refs);
;   rdi = buf, rsi = len, rdx = refs_out, rcx = max_refs
;   Returns rax = n_refs parsed (≥0), or -1 on structural error.
;
; Accepts the corpus shape:
;   [ {"vector":[f, f, ..., f (×14)], "label":"legit"|"fraud"}, ... ]
;
; Whitespace tolerated anywhere.  Unknown keys are skipped via skip_value.
; Label is 1 iff exactly "fraud" (5 chars), else 0.
;
; Stack frame: 6 push + sub 40  →  rsp 0 mod 16 ✓
;   [rsp +  0..7]   double scratch for parse_number
;   [rsp + 16..19]  dim counter (i32)
;   [rsp + 20..39]  pad

global parse_refs
parse_refs:
    push    rbx                          ; p
    push    rbp                          ; end
    push    r12                          ; refs_base
    push    r13                          ; n_refs
    push    r14                          ; max_refs
    push    r15                          ; current ref ptr / scratch
    sub     rsp, 40

    mov     rbx, rdi
    lea     rbp, [rdi + rsi]
    mov     r12, rdx
    xor     r13d, r13d
    mov     r14, rcx

    mov     rdi, rbx
    mov     rsi, rbp
    call    skip_ws
    mov     rbx, rax
    cmp     rbx, rbp
    jae     .fail
    cmp     byte [rbx], '['
    jne     .fail
    inc     rbx

.outer:
    mov     rdi, rbx
    mov     rsi, rbp
    call    skip_ws
    mov     rbx, rax
    cmp     rbx, rbp
    jae     .done
    movzx   eax, byte [rbx]
    cmp     al, ']'
    je      .end_arr
    cmp     al, ','
    jne     .check_obj
    inc     rbx
    jmp     .outer

.check_obj:
    cmp     al, '{'
    jne     .fail
    inc     rbx

    ; Bounds check: n_refs < max_refs
    cmp     r13, r14
    jae     .fail

    ; Current ref ptr = refs_base + n * 64
    mov     r15, r13
    shl     r15, 6
    add     r15, r12

    ; Zero the 64-byte ref slot
    pxor    xmm0, xmm0
    movdqu  [r15 + 0],  xmm0
    movdqu  [r15 + 16], xmm0
    movdqu  [r15 + 32], xmm0
    movdqu  [r15 + 48], xmm0

.fields:
    mov     rdi, rbx
    mov     rsi, rbp
    call    skip_ws
    mov     rbx, rax
    cmp     rbx, rbp
    jae     .fail
    movzx   eax, byte [rbx]
    cmp     al, '}'
    je      .end_obj
    cmp     al, ','
    jne     .key_quote
    inc     rbx
    jmp     .fields

.key_quote:
    cmp     al, '"'
    jne     .fail
    inc     rbx

    mov     rdx, rbx                     ; key start
.key_scan:
    cmp     rbx, rbp
    jae     .fail
    cmp     byte [rbx], '"'
    je      .key_done
    inc     rbx
    jmp     .key_scan
.key_done:
    mov     rcx, rbx
    sub     rcx, rdx                     ; key length
    inc     rbx                          ; past closing "

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
    mov     rbx, rax

    ; Dispatch: vector (6) or label (5) or other → skip_value
    cmp     rcx, 6
    jne     .check_label
    cmp     dword [rdx], 'vect'
    jne     .skip_val
    cmp     word  [rdx + 4], 'or'
    jne     .skip_val
    jmp     .h_vector

.check_label:
    cmp     rcx, 5
    jne     .skip_val
    cmp     dword [rdx], 'labe'
    jne     .skip_val
    cmp     byte  [rdx + 4], 'l'
    jne     .skip_val
    jmp     .h_label

; ---- vector handler -------------------------------------------------------
.h_vector:
    cmp     rbx, rbp
    jae     .fail
    cmp     byte [rbx], '['
    jne     .fail
    inc     rbx

    mov     dword [rsp + 16], 0          ; dim = 0
.vec_loop:
    cmp     dword [rsp + 16], N_DIMS
    jge     .vec_close

    mov     rdi, rbx
    mov     rsi, rbp
    call    skip_ws
    mov     rbx, rax

    mov     rdi, rbx
    mov     rsi, rbp
    lea     rdx, [rsp + 0]
    call    parse_number
    mov     rbx, rax

    ; float = (float)double; store at v[dim]
    cvtsd2ss xmm0, qword [rsp + 0]
    mov     ecx, [rsp + 16]
    movss   [r15 + REF_VEC_OFF + rcx*4], xmm0
    inc     ecx
    mov     [rsp + 16], ecx

    mov     rdi, rbx
    mov     rsi, rbp
    call    skip_ws
    mov     rbx, rax

    cmp     rbx, rbp
    jae     .fail
    movzx   eax, byte [rbx]
    cmp     al, ','
    jne     .vec_loop                    ; no comma → try to close
    inc     rbx
    jmp     .vec_loop

.vec_close:
    mov     rdi, rbx
    mov     rsi, rbp
    call    skip_ws
    mov     rbx, rax
    cmp     rbx, rbp
    jae     .fail
    cmp     byte [rbx], ']'
    jne     .fail
    inc     rbx
    jmp     .fields

; ---- label handler --------------------------------------------------------
.h_label:
    cmp     rbx, rbp
    jae     .fail
    cmp     byte [rbx], '"'
    jne     .fail
    inc     rbx

    mov     rdx, rbx                     ; label start
.lbl_scan:
    cmp     rbx, rbp
    jae     .fail
    cmp     byte [rbx], '"'
    je      .lbl_done
    inc     rbx
    jmp     .lbl_scan
.lbl_done:
    mov     rcx, rbx
    sub     rcx, rdx                     ; label length
    inc     rbx                          ; past closing "

    xor     eax, eax
    cmp     rcx, 5
    jne     .lbl_set
    cmp     dword [rdx], 'frau'
    jne     .lbl_set
    cmp     byte [rdx + 4], 'd'
    jne     .lbl_set
    mov     eax, 1
.lbl_set:
    mov     [r15 + REF_LABEL_OFF], al
    jmp     .fields

; ---- skip unknown value ---------------------------------------------------
.skip_val:
    mov     rdi, rbx
    mov     rsi, rbp
    call    skip_value
    mov     rbx, rax
    jmp     .fields

.end_obj:
    inc     rbx
    inc     r13                          ; n_refs++
    jmp     .outer

.end_arr:
    inc     rbx
.done:
    mov     rax, r13
    add     rsp, 40
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret

.fail:
    mov     rax, -1
    add     rsp, 40
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret

; ---- l2sq_f32 ------------------------------------------------------------
; float l2sq_f32(const float *a, const float *b);
;   rdi = a, rsi = b   (each ≥ 14 floats; lanes 14,15 ignored via mask)
;   returns the squared Euclidean distance over the first 14 lanes in xmm0.
;
; Two 8-wide loads per operand; subtract; the second diff is masked so lanes
; 6 and 7 (i.e. dims 14, 15) contribute 0.  d0² fused with d1² via vfmadd231.

global l2sq_f32
l2sq_f32:
    vmovups      ymm0, [rdi]              ; a[0..7]
    vmovups      ymm1, [rdi + 32]         ; a[8..15]  (lanes 6,7 are pad data)
    vmovups      ymm2, [rsi]              ; b[0..7]
    vmovups      ymm3, [rsi + 32]         ; b[8..15]
    vsubps       ymm0, ymm0, ymm2         ; d0 = a - b   (low half)
    vsubps       ymm1, ymm1, ymm3         ; d1 = a - b   (high half, w/ pad lanes)
    vmovaps      ymm2, [c_dim_mask]
    vmulps       ymm1, ymm1, ymm2         ; zero d1 lanes 6,7
    vmulps       ymm0, ymm0, ymm0         ; d0²
    vfmadd231ps  ymm0, ymm1, ymm1         ; d0² + d1²

    ; Horizontal sum of 8 floats → low lane of xmm0.
    vextractf128 xmm1, ymm0, 1
    vaddps       xmm0, xmm0, xmm1         ; reduces to 4 floats
    vhaddps      xmm0, xmm0, xmm0
    vhaddps      xmm0, xmm0, xmm0
    vzeroupper
    ret

; ---- kmeans ---------------------------------------------------------------
; void kmeans(const void *refs, size_t n,
;             float (*centroids)[16],
;             int32_t *assignments,
;             int n_iters);
;   rdi = refs, rsi = n, rdx = centroids, rcx = assignments, r8 = n_iters
;
; Init: evenly-spaced sample (refs[c*step].v[0..13] → centroids[c][0..13];
; lanes 14, 15 forced to 0 by the dim mask).
;
; Iteration:
;   Phase A (assign): for each i, scan all 2048 centroids, store argmin in
;     assignments[i].  ~5.9 ns × 2048 = ~12 μs per ref → ~36 s for 3M refs.
;   Phase B (recompute): zero sums[K][14] (double) + counts[K] (u64); single
;     pass accumulating, then divide; write back into centroids.
;
; Stack layout (6 push + sub 80 → rsp 0 mod 16):
;   [rsp +  0..3]   best_d (float)
;   [rsp +  4..7]   i_loop counter cache
;   [rsp +  8..15]  step (u64)
;   [rsp + 16..23]  sums ptr   (mmap'd, 2048×14 × 8 = 229 376 B)
;   [rsp + 24..31]  counts ptr (2048 × 8 = 16 384 B)
;   [rsp + 32..35]  n_iters
;   [rsp + 36..39]  current iter
;   [rsp + 40..47]  refs ptr cache
;   [rsp + 48..79]  scratch / pad

%define KM_SUMS_BYTES   (N_CLUSTERS * N_DIMS * 8)
%define KM_COUNTS_BYTES (N_CLUSTERS * 8)
%define KM_TOTAL_BYTES  (KM_SUMS_BYTES + KM_COUNTS_BYTES)

global kmeans
kmeans:
    push    rbx                          ; refs
    push    rbp                          ; n
    push    r12                          ; centroids
    push    r13                          ; assignments
    push    r14                          ; sums
    push    r15                          ; counts
    sub     rsp, 80

    mov     rbx, rdi
    mov     rbp, rsi
    mov     r12, rdx
    mov     r13, rcx
    mov     [rsp + 32], r8d              ; n_iters
    mov     [rsp + 48], r9d              ; k (cluster count; stashed — l2sq calls clobber r9)

    ; --- init centroids: step = n / k -----------------------------------
    mov     rax, rbp
    xor     edx, edx
    mov     ecx, [rsp + 48]              ; k
    div     rcx
    mov     [rsp + 8], rax               ; step

    xor     ecx, ecx
.init_loop:
    cmp     ecx, [rsp + 48]              ; k
    jge     .init_done

    ; src = refs + (c * step) * 64
    mov     rax, [rsp + 8]
    mul     rcx
    shl     rax, 6
    lea     rdi, [rbx + rax]
    ; dst = centroids + c * 64
    mov     rax, rcx
    shl     rax, 6
    lea     rsi, [r12 + rax]
    ; Copy 14 floats; lanes 14,15 forced to 0 via mask on the high half
    vmovups ymm0, [rdi]
    vmovups ymm1, [rdi + 32]
    vmulps  ymm1, ymm1, [c_dim_mask]
    vmovups [rsi],      ymm0
    vmovups [rsi + 32], ymm1

    inc     ecx
    jmp     .init_loop
.init_done:
    vzeroupper

    ; --- mmap sums + counts as one anonymous region ---------------------
    xor     edi, edi
    mov     esi, KM_TOTAL_BYTES
    mov     edx, PROT_READ | PROT_WRITE
    mov     r10d, MAP_PRIVATE | MAP_ANONYMOUS
    mov     r8, -1
    xor     r9, r9
    syscall0 SYS_mmap
    cmp     rax, -4095
    jae     .ret                         ; mmap failed; bail (caller sees no change)
    mov     r14, rax                     ; sums
    lea     r15, [rax + KM_SUMS_BYTES]   ; counts
    mov     [rsp + 16], r14
    mov     [rsp + 24], r15

    ; --- iteration loop --------------------------------------------------
    mov     dword [rsp + 36], 0
.iter:
    mov     eax, [rsp + 36]
    cmp     eax, [rsp + 32]
    jge     .iter_done

    ; -------- Phase A: assignments --------
    xor     ecx, ecx
    mov     [rsp + 4], ecx               ; i = 0
.assign_i:
    mov     ecx, [rsp + 4]
    cmp     rcx, rbp
    jae     .recompute

    ; ref_ptr = refs + i * 64; cache in [rsp + 40]
    mov     rax, rcx
    shl     rax, 6
    lea     rsi, [rbx + rax]
    mov     [rsp + 40], rsi

    ; best_d = l2sq(ref, centroids[0]); best_c = 0  → r15d as scratch
    mov     rdi, rsi
    mov     rsi, r12
    call    l2sq_f32
    movss   [rsp + 0], xmm0
    xor     r10d, r10d                   ; best_c (caller-save reg)
    mov     [rsp + 52], r10d             ; stash for use across calls

    mov     r11d, 1
.assign_c:
    cmp     r11d, [rsp + 48]             ; k
    jge     .assign_i_done

    mov     rdi, [rsp + 40]              ; ref_ptr
    mov     rax, r11
    shl     rax, 6
    lea     rsi, [r12 + rax]             ; centroid_ptr
    mov     [rsp + 56], r11d
    call    l2sq_f32
    mov     r11d, [rsp + 56]

    movss   xmm1, [rsp + 0]
    ucomiss xmm0, xmm1
    jae     .assign_c_no_update
    movss   [rsp + 0], xmm0
    mov     [rsp + 52], r11d
.assign_c_no_update:
    inc     r11d
    jmp     .assign_c

.assign_i_done:
    mov     ecx, [rsp + 4]
    mov     eax, [rsp + 52]
    mov     [r13 + rcx*4], eax           ; assignments[i] = best_c
    inc     ecx
    mov     [rsp + 4], ecx
    jmp     .assign_i

.recompute:
    ; Zero sums (KM_SUMS_BYTES) and counts (KM_COUNTS_BYTES)
    mov     rdi, r14
    xor     eax, eax
    mov     ecx, KM_TOTAL_BYTES / 8
    cld
    rep     stosq

    ; Accumulate:  for i in 0..n-1: c = assignments[i]; counts[c]++;
    ;                                for d: sums[c*14+d] += refs[i].v[d]
    xor     ecx, ecx
.acc_loop:
    cmp     rcx, rbp
    jae     .divide

    mov     esi, [r13 + rcx*4]           ; esi = assignments[i] = c
    ; counts[c]++
    inc     qword [r15 + rsi*8]

    ; sums_row = sums + c * 14 * 8 = sums + c * 112
    mov     rax, rsi
    imul    rax, rax, N_DIMS * 8
    lea     rdi, [r14 + rax]             ; sums_row

    ; ref vector ptr
    mov     rax, rcx
    shl     rax, 6
    lea     rdx, [rbx + rax]

    ; Unrolled add of 14 floats → 14 doubles
    %assign D 0
    %rep N_DIMS
        movss   xmm0, [rdx + D*4]
        cvtss2sd xmm0, xmm0
        addsd   xmm0, [rdi + D*8]
        movsd   [rdi + D*8], xmm0
    %assign D D+1
    %endrep

    inc     rcx
    jmp     .acc_loop

.divide:
    ; for c in 0..k-1: if counts[c] > 0: inv = 1/counts[c]; centroid[d] = sum[d] * inv
    xor     ecx, ecx
.div_c:
    cmp     ecx, [rsp + 48]             ; k
    jge     .iter_step

    mov     rax, [r15 + rcx*8]           ; counts[c]
    test    rax, rax
    jz      .div_c_skip

    cvtsi2sd xmm1, rax                   ; (double)counts
    movsd   xmm2, [c_one_d]
    divsd   xmm2, xmm1                   ; inv = 1 / counts

    mov     rax, rcx
    imul    rax, rax, N_DIMS * 8
    lea     rsi, [r14 + rax]             ; sums_row
    mov     rax, rcx
    shl     rax, 6
    lea     rdi, [r12 + rax]             ; centroid_row

    %assign D 0
    %rep N_DIMS
        movsd   xmm0, [rsi + D*8]
        mulsd   xmm0, xmm2
        cvtsd2ss xmm0, xmm0
        movss   [rdi + D*4], xmm0
    %assign D D+1
    %endrep

.div_c_skip:
    inc     ecx
    jmp     .div_c

.iter_step:
    inc     dword [rsp + 36]
    jmp     .iter

.iter_done:
    ; munmap(sums, KM_TOTAL_BYTES)
    mov     rdi, [rsp + 16]
    mov     esi, KM_TOTAL_BYTES
    syscall0 SYS_munmap

.ret:
    add     rsp, 80
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret

; ---- counting_sort_by_cluster --------------------------------------------
; void counting_sort_by_cluster(
;     const int32_t *assignments,    // rdi
;     size_t n,                       // rsi
;     uint32_t *cluster_offsets,     // rdx  (output, size K+1; zeroed inside)
;     uint32_t *order,               // rcx  (output, size n)
;     uint32_t *cursor);             // r8   (scratch, size K)
;
; cluster_offsets ends as the canonical prefix-sum (cluster_offsets[c+1] -
; cluster_offsets[c] = size of cluster c).  order[pos] = original index that
; lands at output position pos.

global counting_sort_by_cluster
counting_sort_by_cluster:
    push    rbx                          ; assignments
    push    rbp                          ; n
    push    r12                          ; cluster_offsets
    push    r13                          ; order
    push    r14                          ; cursor
    sub     rsp, 8                        ; 5 push + 8 → rsp 0 mod 16

    mov     rbx, rdi
    mov     rbp, rsi
    mov     r12, rdx
    mov     r13, rcx
    mov     r14, r8
    ; r9d = k (cluster count). No CALL in this function, so r9 survives
    ; throughout; used directly as the loop bound below.

    ; Zero cluster_offsets[0..k]
    mov     rdi, r12
    xor     eax, eax
    lea     ecx, [r9 + 1]                 ; k + 1
    cld
    rep     stosd

    ; Count: cluster_offsets[assignments[i] + 1]++
    xor     rcx, rcx
.count:
    cmp     rcx, rbp
    jae     .count_done
    mov     eax, [rbx + rcx*4]
    inc     dword [r12 + rax*4 + 4]
    inc     rcx
    jmp     .count
.count_done:

    ; Prefix sum: cluster_offsets[c+1] += cluster_offsets[c]
    xor     ecx, ecx
.psum:
    cmp     ecx, r9d                     ; k
    jge     .psum_done
    mov     eax, [r12 + rcx*4]
    add     [r12 + rcx*4 + 4], eax
    inc     ecx
    jmp     .psum
.psum_done:

    ; cursor = copy of cluster_offsets[0..k-1]
    mov     rdi, r14
    mov     rsi, r12
    mov     ecx, r9d                     ; k
    cld
    rep     movsd

    ; Distribute: order[cursor[c]++] = i
    xor     rcx, rcx
.dist:
    cmp     rcx, rbp
    jae     .dist_done
    mov     eax, [rbx + rcx*4]            ; c = assignments[i]
    mov     edx, [r14 + rax*4]            ; pos = cursor[c]
    mov     [r13 + rdx*4], ecx
    inc     dword [r14 + rax*4]
    inc     rcx
    jmp     .dist
.dist_done:

    add     rsp, 8
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret

; ---- bbox_pack -----------------------------------------------------------
; void bbox_pack(
;     const void *refs, size_t n, const uint32_t *order,
;     const uint32_t *cluster_offsets,
;     int16_t *bbox_min, int16_t *bbox_max,
;     int16_t **pair_arr,           // arg7 (stack): array of 7 pointers
;     uint8_t *labels_out);         // arg8 (stack)
;
; For each ordered ref: quantize 14 f32 → 16 i16 (lanes 14,15 forced 0),
; merge into the per-cluster bbox (vpminsw/vpmaxsw), write label, and stripe
; into the 7 SoA pair arrays.  cid advances via a linear cursor; total O(n+K).
;
; bbox_min initialized to INT16_MAX on lanes 0..13, 0 on lanes 14..15.
; bbox_max initialized to INT16_MIN on lanes 0..13, 0 on lanes 14..15.

global bbox_pack
bbox_pack:
    ; Snapshot stack args (arg7, arg8, arg9) BEFORE the prologue, while their
    ; offsets are trivially [rsp + 8] / [rsp + 16] / [rsp + 24].  This makes the
    ; reader immune to future push/sub layout changes.  r10/r11/rax are
    ; caller-saved and unused by SysV for the first six arguments.
    mov     r10, [rsp + 8]                ; pair_arr (arg7)
    mov     r11, [rsp + 16]               ; labels_out (arg8)
    mov     rax, [rsp + 24]               ; k (arg9)

    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 56                       ; 6 push + 56 → rsp 0 mod 16

    mov     rbx, rdi                      ; refs
    mov     rbp, rsi                      ; n
    mov     r12, rdx                      ; order
    mov     r13, rcx                      ; cluster_offsets
    mov     r14, r8                       ; bbox_min
    mov     r15, r9                       ; bbox_max

    mov     [rsp + 0], r10                ; pair_arr ptrs base
    mov     [rsp + 8], r11                ; labels_out
    mov     [rsp + 48], eax               ; k (cluster count)

    ; --- Init bbox per cluster ----
    ; For each c in 0..K-1, set bbox_min lanes 0..13 = INT16_MAX, 14..15 = 0.
    ; bbox_max lanes 0..13 = INT16_MIN.
    ; Build per-cluster initializers in YMM.
    vmovdqu ymm2, [c_bbox_min_init]
    vmovdqu ymm3, [c_bbox_max_init]
    xor     ecx, ecx
.init_bbox:
    cmp     ecx, [rsp + 48]              ; k
    jge     .init_done
    mov     eax, ecx
    shl     eax, 5                        ; c * 32
    vmovdqu [r14 + rax], ymm2
    vmovdqu [r15 + rax], ymm3
    inc     ecx
    jmp     .init_bbox
.init_done:

    ; --- Walk order[] ----
    xor     r10d, r10d                    ; cid = 0
    xor     r11d, r11d                    ; pos = 0

.outer:
    cmp     r11, rbp
    jae     .pack_done

    ; Advance cid while cluster_offsets[cid+1] <= pos
.advance_cid:
    mov     eax, [r13 + r10*4 + 4]
    cmp     eax, r11d
    ja      .have_cid
    inc     r10
    jmp     .advance_cid
.have_cid:

    ; orig = order[pos]; ref = refs + orig*64
    mov     eax, [r12 + r11*4]
    mov     rdi, rax
    shl     rdi, 6
    add     rdi, rbx                      ; rdi = ref ptr

    ; labels_out[pos] = ref->label
    mov     rsi, [rsp + 8]
    movzx   eax, byte [rdi + 56]
    mov     [rsi + r11], al

    ; --- Quantize 16 floats → 16 i16, lanes 14,15 forced to 0 ----
    vmovups ymm0, [rdi]
    vmovups ymm1, [rdi + 32]
    vmulps  ymm1, ymm1, [c_dim_mask]      ; zero lanes 14,15
    vmulps  ymm0, ymm0, [c_scale_f32_vec] ; * SCALE
    vmulps  ymm1, ymm1, [c_scale_f32_vec]
    vcvtps2dq ymm0, ymm0                  ; round per MXCSR (nearest-even)
    vcvtps2dq ymm1, ymm1
    vpackssdw ymm0, ymm0, ymm1            ; pack i32→i16 saturating
    vpermq  ymm0, ymm0, 0xD8              ; fix lane order: [a_lo,a_hi,b_lo,b_hi]
    vmovdqu [rsp + 16], ymm0              ; qv[0..15]

    ; --- Vectorized bbox update ----
    mov     eax, r10d
    shl     eax, 5                        ; cid * 32
    vmovdqu ymm2, [r14 + rax]             ; bbox_min[cid]
    vmovdqu ymm3, [r15 + rax]             ; bbox_max[cid]
    vpminsw ymm2, ymm2, ymm0
    vpmaxsw ymm3, ymm3, ymm0
    vmovdqu [r14 + rax], ymm2
    vmovdqu [r15 + rax], ymm3

    ; --- Pack into 7 pair arrays ----
    mov     rsi, [rsp + 0]                ; pair_arr base
    mov     edx, r11d                     ; pos as u32, scale by 4 below
%assign P 0
%rep N_PAIRS
    mov     eax, [rsp + 16 + P*4]         ; qv pair p (two i16 as one i32)
    mov     rdi, [rsi + P*8]              ; pair_arr[p]
    mov     [rdi + rdx*4], eax
%assign P P+1
%endrep

    inc     r11
    jmp     .outer

.pack_done:
    vzeroupper
    add     rsp, 56
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret

; ---- write_padded helper -------------------------------------------------
; ssize_t write_padded(int fd, const void *buf, size_t n);
;   Writes `n` bytes, then enough zeros to round up to 64.  Returns 0 on
;   full write success, -1 on any write error.  Uses fd in rdi, buf in rsi,
;   n in rdx.  Internal: small static zero buffer for the pad.

section .rodata
align 64
zero_pad_64:    times 64 db 0

section .text

write_padded:
    push    rbx                          ; fd
    push    rbp                          ; buf
    push    r12                          ; n
    sub     rsp, 8                        ; align

    mov     ebx, edi
    mov     rbp, rsi
    mov     r12, rdx

    ; Inner write loop for `buf, n`.  bytes_written lives in [rsp + 0]
    ; (r13 NOT used — we did not push it, so must not touch it).
    mov     qword [rsp + 0], 0
.wloop:
    mov     rax, [rsp + 0]
    cmp     rax, r12
    jae     .wdone
    mov     edi, ebx
    lea     rsi, [rbp + rax]
    mov     rdx, r12
    sub     rdx, rax
    syscall0 SYS_write
    test    rax, rax
    js      .check_eintr
    add     [rsp + 0], rax
    jmp     .wloop
.check_eintr:
    cmp     rax, -EINTR
    je      .wloop
    jmp     .err
.wdone:

    ; Padding: write zeros to round up to 64
    mov     rax, r12
    and     rax, 63
    test    rax, rax
    jz      .ok
    mov     edi, 64
    sub     edi, eax                     ; pad_bytes (1..63)
    movsxd  rdx, edi
    mov     edi, ebx
    lea     rsi, [zero_pad_64]
    syscall0 SYS_write
    test    rax, rax
    js      .err

.ok:
    xor     eax, eax
    add     rsp, 8
    pop     r12
    pop     rbp
    pop     rbx
    ret
.err:
    mov     eax, -1
    add     rsp, 8
    pop     r12
    pop     rbp
    pop     rbx
    ret

; ---- write_index_bin -----------------------------------------------------
; int write_index_bin(
;     int fd, uint32_t n,
;     const uint32_t *cluster_offsets,
;     const int16_t *bbox_min, const int16_t *bbox_max,
;     int16_t **pair_arr,           // arg6
;     const uint8_t *labels);       // arg7
; Returns 0 on success, -1 on any write error.
;
; File layout (all sections 64-byte padded):
;     header (64)
;     cluster_offsets ((K+1) * 4)
;     bbox_min (K * 32)
;     bbox_max (K * 32)
;     pair_arr[0..6]  (each n * 4)
;     labels (n)
;     tail pad (64)

global write_index_bin
write_index_bin:
    ; Snapshot stack args (arg7 labels, arg8 k) BEFORE the prologue while they
    ; sit at [rsp+8] / [rsp+16].  r10/r11 are caller-saved and unused by SysV
    ; for the first six args, so we park them there until we have local slots.
    mov     r10, [rsp + 8]                ; labels (arg7)
    mov     r11, [rsp + 16]               ; k (arg8)

    push    rbx                          ; fd
    push    rbp                          ; n (i64 for convenience)
    push    r12                          ; cluster_offsets
    push    r13                          ; bbox_min
    push    r14                          ; bbox_max
    push    r15                          ; pair_arr
    sub     rsp, 88                       ; locals: 64B header buf + slots

    mov     ebx, edi
    mov     ebp, esi
    mov     r12, rdx
    mov     r13, rcx
    mov     r14, r8
    mov     r15, r9
    mov     [rsp + 64], r10               ; labels
    mov     [rsp + 72], r11d              ; k (survives the write_padded calls)

    ; --- Header (64 B): magic + n_clusters + n_vectors + zero tail ----
    pxor    xmm0, xmm0
    movdqu  [rsp + 0],  xmm0
    movdqu  [rsp + 16], xmm0
    movdqu  [rsp + 32], xmm0
    movdqu  [rsp + 48], xmm0
    mov     rax, 0x5844492D34484E52        ; "RNH4-IDX" little-endian
    mov     [rsp + 0], rax
    mov     eax, [rsp + 72]                ; k
    mov     [rsp + 8], eax                 ; header n_clusters = k
    mov     [rsp + 12], ebp                ; n_vectors

    mov     edi, ebx
    lea     rsi, [rsp + 0]
    mov     edx, 64
    call    write_padded
    test    eax, eax
    jnz     .fail

    ; --- cluster_offsets ((k+1) * 4 bytes) ----
    mov     edi, ebx
    mov     rsi, r12
    mov     edx, [rsp + 72]               ; k
    inc     edx
    shl     edx, 2                        ; (k+1) * 4
    call    write_padded
    test    eax, eax
    jnz     .fail

    ; --- bbox_min (k * 16 * 2 bytes) ----
    mov     edi, ebx
    mov     rsi, r13
    mov     edx, [rsp + 72]               ; k
    shl     edx, 5                        ; k * 32
    call    write_padded
    test    eax, eax
    jnz     .fail

    ; --- bbox_max ----
    mov     edi, ebx
    mov     rsi, r14
    mov     edx, [rsp + 72]               ; k
    shl     edx, 5                        ; k * 32
    call    write_padded
    test    eax, eax
    jnz     .fail

    ; --- pair_arr[0..6]: each n * 4 bytes ----
%assign P 0
%rep N_PAIRS
    mov     edi, ebx
    mov     rsi, [r15 + P*8]
    mov     rdx, rbp
    shl     rdx, 2                        ; n * 4
    call    write_padded
    test    eax, eax
    jnz     .fail
%assign P P+1
%endrep

    ; --- labels (n bytes, NO padding section but the tail-pad below) ----
    xor     r10, r10                      ; bytes written
.lbl_loop:
    cmp     r10, rbp
    jae     .lbl_done
    mov     edi, ebx
    mov     rsi, [rsp + 64]
    add     rsi, r10
    mov     rdx, rbp
    sub     rdx, r10
    syscall0 SYS_write
    test    rax, rax
    js      .lbl_intr
    add     r10, rax
    jmp     .lbl_loop
.lbl_intr:
    cmp     rax, -EINTR
    je      .lbl_loop
    jmp     .fail
.lbl_done:

    ; --- Tail pad (64 bytes) so the runtime SIMD over-read can't cross
    ;     the file mapping boundary on the last partial batch ----
    mov     edi, ebx
    lea     rsi, [zero_pad_64]
    mov     edx, 64
    syscall0 SYS_write
    test    rax, rax
    js      .fail

    xor     eax, eax
    add     rsp, 88
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret

.fail:
    mov     eax, -1
    add     rsp, 88
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret

; ---- bbox initializers (in .rodata) --------------------------------------
section .rodata
align 32
c_bbox_min_init:                     ; lanes 0..13 = INT16_MAX, 14..15 = 0
    dw 0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF
    dw 0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF, 0x7FFF, 0x0000, 0x0000
align 32
c_bbox_max_init:                     ; lanes 0..13 = INT16_MIN, 14..15 = 0
    dw 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000
    dw 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x8000, 0x0000, 0x0000

section .text

; ---- _start ---------------------------------------------------------------
; Entry: argv[1] = input JSON path, argv[2] = output bin path.

%define MAX_REFS    3500000
%define REFS_BYTES  (MAX_REFS * REF_SIZE)        ; 224 MB
%define K_TIMES_16  (N_CLUSTERS * 16)
%define CENTROIDS_BYTES  (K_TIMES_16 * 4)        ; 128 KB
%define ASSIGN_BYTES     (MAX_REFS * 4)          ; 14 MB
%define OFFSETS_BYTES    ((N_CLUSTERS + 1) * 4)
%define ORDER_BYTES      (MAX_REFS * 4)
%define CURSOR_BYTES     (N_CLUSTERS * 4)
%define BBOX_BYTES       (N_CLUSTERS * 16 * 2)
%define LABELS_BYTES     MAX_REFS
%define PAIR_BYTES       (MAX_REFS * 2 * 2)      ; per pair array

%define KMEANS_ITERS     20

; ---- filter_refs_by_tag --------------------------------------------------
; size_t filter_refs_by_tag(void *refs, size_t n, int partition_tag);
;   rdi = refs ptr, rsi = n, edx = tag (0..3)
;   Returns rax = new n after compacting in place to keep only refs whose
;   (unknown_merchant, has_last_tx) matches the partition tag.
;
; tag encoding: ((vec[11] > 0.5) << 1) | (vec[5] >= 0)
;   tag=0 -> known + no_last     (vec[11] <= 0.5, vec[5] <  0)
;   tag=1 -> known + has_last    (vec[11] <= 0.5, vec[5] >= 0)
;   tag=2 -> unknown + no_last   (vec[11] >  0.5, vec[5] <  0)
;   tag=3 -> unknown + has_last  (vec[11] >  0.5, vec[5] >= 0)
;
; Ref layout: 14 f32 starting at +0 (REF_VEC_OFF=0); 64 B per ref.
; vec[5] at byte offset 20, vec[11] at byte offset 44.
;
; Stable in-place compaction (single pass).  Source/dest indices use rep movsq
; (8 qwords = 64 B per ref).

global filter_refs_by_tag
filter_refs_by_tag:
    push    rbx                          ; refs base
    push    rbp                          ; n
    push    r12                          ; tag
    push    r13                          ; src index
    push    r14                          ; dst index
    push    r15                          ; scratch (zero, half)

    mov     rbx, rdi
    mov     rbp, rsi
    mov     r12d, edx

    xor     r13, r13                     ; src = 0
    xor     r14, r14                     ; dst = 0
    pxor    xmm2, xmm2                   ; zero (for vec[5] >= 0 compare)
    movss   xmm3, [c_half_f]             ; 0.5 (for vec[11] > 0.5 compare)
.loop:
    cmp     r13, rbp
    jge     .done

    mov     rax, r13
    shl     rax, 6                       ; src offset
    lea     rdi, [rbx + rax]

    ; Compute tag for this ref.  unknown = vec[11] > 0.5, has_last = vec[5] >= 0
    movss   xmm0, [rdi + 20]             ; vec[5]
    movss   xmm1, [rdi + 44]             ; vec[11]
    xor     ecx, ecx
    ucomiss xmm1, xmm3
    seta    cl                            ; cl = 1 if vec[11] > 0.5
    shl     ecx, 1
    xor     r15d, r15d
    ucomiss xmm0, xmm2
    setae   r15b                          ; r15b = 1 if vec[5] >= 0
    or      ecx, r15d
    ; ecx = current tag (0..3)
    cmp     ecx, r12d
    jne     .skip

    ; Match — copy ref from src to dst (only if src != dst).
    cmp     r13, r14
    je      .keep_inplace
    mov     rcx, r14
    shl     rcx, 6
    lea     rsi, [rbx + rax]             ; src ptr
    lea     rdi, [rbx + rcx]             ; dst ptr
    ; 64 B copy via 4 xmm loads/stores (faster than rep movsq for small N)
    movdqu  xmm4, [rsi]
    movdqu  xmm5, [rsi + 16]
    movdqu  xmm6, [rsi + 32]
    movdqu  xmm7, [rsi + 48]
    movdqu  [rdi],      xmm4
    movdqu  [rdi + 16], xmm5
    movdqu  [rdi + 32], xmm6
    movdqu  [rdi + 48], xmm7
.keep_inplace:
    inc     r14
.skip:
    inc     r13
    jmp     .loop

.done:
    mov     rax, r14                     ; new n
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret

section .rodata
align 4
c_half_f:    dd 0x3F000000               ; 0.5 f32
section .text

global _start
_start:
    mov     rax, [rsp]                   ; argc
    cmp     rax, 4                       ; need: input output tag
    jl      .usage

    mov     r14, [rsp + 16]              ; argv[1] = input
    mov     r15, [rsp + 24]              ; argv[2] = output
    ; Parse argv[3] as single-digit partition tag (0..3).  r12 is callee-save
    ; under SysV (and the syscall path here preserves it), so this value
    ; survives every call through the pipeline.
    mov     rax, [rsp + 32]
    movzx   r12d, byte [rax]
    sub     r12d, '0'
    cmp     r12d, N_PARTITIONS
    jae     .usage

    ; Open input file
    mov     rdi, r14
    xor     esi, esi                     ; O_RDONLY
    xor     edx, edx
    syscall0 SYS_open
    test    rax, rax
    js      .err_open_in
    mov     r13d, eax                    ; in_fd

    ; fstat to get size
    sub     rsp, 152
    mov     edi, r13d
    mov     rsi, rsp
    syscall0 SYS_fstat
    test    rax, rax
    js      .err_open_in
    mov     r9, [rsp + 48]               ; in_size = st.st_size
    add     rsp, 152

    ; mmap input file (PRIVATE | POPULATE)
    xor     edi, edi
    mov     rsi, r9
    mov     edx, PROT_READ
    mov     r10d, MAP_PRIVATE | MAP_POPULATE
    mov     r8d, r13d
    push    r9                           ; stash in_size
    xor     r9, r9
    syscall0 SYS_mmap
    pop     r9
    cmp     rax, -4095
    jae     .err_mmap
    mov     [rsp - 8], rax               ; not pushed yet, just temp; redo properly
    ; We have a lot of pointers — use a clean stack frame.

    ; Set up a real frame.  Bail out and rewrite.  For brevity, allocate
    ; a big enough stack frame and store everything by offset.
    ;
    ; Convention from here:
    ;   r12d = argc
    ;   r13d = in_fd
    ;   r14  = argv[1]      (kept)
    ;   r15  = argv[2]      (kept)
    ;   stack slots:
    ;     [rsp +  0]  in_buf    (mmap'd file)
    ;     [rsp +  8]  in_size
    ;     [rsp + 16]  refs
    ;     [rsp + 24]  n_refs
    ;     [rsp + 32]  centroids
    ;     [rsp + 40]  assignments
    ;     [rsp + 48]  cluster_offsets
    ;     [rsp + 56]  order
    ;     [rsp + 64]  cursor
    ;     [rsp + 72]  bbox_min
    ;     [rsp + 80]  bbox_max
    ;     [rsp + 88]  labels_out
    ;     [rsp + 96..151]  7 pair_arr ptrs (56 B)
    ;     [rsp + 152]  out_fd (i32 + pad)

    sub     rsp, 192
    mov     [rsp + 0], rax
    mov     [rsp + 8], r9

    ; allocate refs buffer (224 MB)
    mov     rdi, REFS_BYTES
    call    mmap_alloc
    cmp     rax, -4095
    jae     .err_mmap
    mov     [rsp + 16], rax

    ; parse_refs(in_buf, in_size, refs, MAX_REFS)
    mov     rdi, [rsp + 0]
    mov     rsi, [rsp + 8]
    mov     rdx, [rsp + 16]
    mov     rcx, MAX_REFS
    call    parse_refs
    test    rax, rax
    js      .err_parse
    mov     [rsp + 24], rax              ; stash full n

    ; Filter refs in place by partition tag (in r12d).  Refs not matching
    ; the tag are discarded; remaining ones compacted into the front of the
    ; buffer.  Returns new n_refs ≤ original.
    mov     rdi, [rsp + 16]
    mov     esi, [rsp + 24]              ; full n (pre-filter)
    mov     edx, r12d
    call    filter_refs_by_tag
    mov     [rsp + 24], rax              ; n_refs (post-filter)

    ; --- Adaptive cluster count: k = clamp(n / 300, 64, N_CLUSTERS) ---------
    ; Small partitions want few clusters (phase-1 cost dominates → floor 64);
    ; large ones want many (per-cluster scan dominates → cap N_CLUSTERS=2048).
    ; Stashed at [rsp+160] (free slot past out_fd) and threaded into kmeans /
    ; counting_sort / bbox_pack / write_index_bin.  Exact regardless of k.
    xor     edx, edx
    mov     ecx, 300
    div     rcx                          ; rax = n / 300
    and     eax, -8                      ; round to multiple of 8 (compute_cluster_packed
                                         ; / pick_min process 8 clusters per ymm; k must
                                         ; be 8-aligned, else build_bpsoa's group math and
                                         ; the packed-array bounds go off by phantom lanes)
    cmp     eax, 64
    jae     .k_lo_ok
    mov     eax, 64
.k_lo_ok:
    cmp     eax, N_CLUSTERS
    jbe     .k_hi_ok
    mov     eax, N_CLUSTERS
.k_hi_ok:
    mov     [rsp + 160], eax             ; k

    ; Allocate centroids, assignments, cluster_offsets, order, cursor, bbox_*
    mov     rdi, CENTROIDS_BYTES
    call    mmap_alloc
    cmp     rax, -4095
    jae     .err_mmap
    mov     [rsp + 32], rax

    mov     rdi, ASSIGN_BYTES
    call    mmap_alloc
    cmp     rax, -4095
    jae     .err_mmap
    mov     [rsp + 40], rax

    mov     rdi, OFFSETS_BYTES + 4096    ; pad
    call    mmap_alloc
    mov     [rsp + 48], rax

    mov     rdi, ORDER_BYTES
    call    mmap_alloc
    mov     [rsp + 56], rax

    mov     rdi, CURSOR_BYTES + 4096
    call    mmap_alloc
    mov     [rsp + 64], rax

    mov     rdi, BBOX_BYTES
    call    mmap_alloc
    mov     [rsp + 72], rax

    mov     rdi, BBOX_BYTES
    call    mmap_alloc
    mov     [rsp + 80], rax

    mov     rdi, [rsp + 24]              ; labels_out: n bytes (round to 4k)
    add     rdi, 4096
    call    mmap_alloc
    mov     [rsp + 88], rax

    ; 7 pair arrays at [rsp + 96 + p*8]  (i16 pairs, n × 4 bytes each)
%assign P 0
%rep N_PAIRS
    mov     rdi, [rsp + 24]
    shl     rdi, 2                        ; n * 4 bytes
    add     rdi, 4096
    call    mmap_alloc
    mov     [rsp + 96 + P*8], rax
%assign P P+1
%endrep

    ; --- kmeans(refs, n, centroids, assignments, 20, k) ----
    mov     rdi, [rsp + 16]
    mov     rsi, [rsp + 24]
    mov     rdx, [rsp + 32]
    mov     rcx, [rsp + 40]
    mov     r8d, KMEANS_ITERS
    mov     r9d, [rsp + 160]             ; k
    call    kmeans

    ; --- counting_sort_by_cluster(assignments, n, offsets, order, cursor, k) ----
    mov     rdi, [rsp + 40]
    mov     rsi, [rsp + 24]
    mov     rdx, [rsp + 48]
    mov     rcx, [rsp + 56]
    mov     r8,  [rsp + 64]
    mov     r9d, [rsp + 160]             ; k
    call    counting_sort_by_cluster

    ; --- bbox_pack(refs, n, order, offsets, bmin, bmax, pair_arr, labels, k) ----
    mov     rdi, [rsp + 16]
    mov     rsi, [rsp + 24]
    mov     rdx, [rsp + 56]
    mov     rcx, [rsp + 48]
    mov     r8,  [rsp + 72]
    mov     r9,  [rsp + 80]
    ; stack args arg7..arg9: load into regs before pushing (rsp not yet shifted)
    lea     r10, [rsp + 96]              ; pair_arr base (arg7)
    mov     r11, [rsp + 88]              ; labels_out (arg8)
    mov     eax, [rsp + 160]            ; k (arg9)
    sub     rsp, 8                       ; pad: 3 qword args need 8B for 16-align
    push    rax                          ; arg9: k
    push    r11                          ; arg8: labels_out
    push    r10                          ; arg7: pair_arr base
    call    bbox_pack
    add     rsp, 32

    ; --- Open output file ----
    mov     rdi, r15
    mov     esi, O_WRONLY | O_CREAT | O_TRUNC
    mov     edx, 0o644
    syscall0 SYS_open
    test    rax, rax
    js      .err_open_out
    mov     [rsp + 152], eax              ; out_fd

    ; --- write_index_bin(out_fd, n, offsets, bmin, bmax, pair_arr, labels, k) ----
    mov     edi, eax
    mov     esi, [rsp + 24]               ; n (low 32 bits)
    mov     rdx, [rsp + 48]
    mov     rcx, [rsp + 72]
    mov     r8,  [rsp + 80]
    lea     r9,  [rsp + 96]
    mov     rax, [rsp + 88]               ; labels (arg7)
    mov     r11d, [rsp + 160]             ; k (arg8)
    push    r11                           ; arg8: k       -> [rsp+16] in callee
    push    rax                           ; arg7: labels  -> [rsp+8]  in callee
    call    write_index_bin
    add     rsp, 16

    ; --- close output ----
    mov     edi, [rsp + 152]
    syscall0 SYS_close

    ; "done"
    mov     edi, STDERR
    lea     rsi, [done_msg]
    mov     edx, done_len
    syscall0 SYS_write

    xor     edi, edi
    syscall0 SYS_exit_group

.usage:
    mov     edi, STDERR
    lea     rsi, [usage_bi_msg]
    mov     edx, usage_bi_len
    syscall0 SYS_write
    mov     edi, 1
    syscall0 SYS_exit_group

.err_open_in:
    mov     edi, STDERR
    lea     rsi, [err_open_in_msg]
    mov     edx, err_open_in_len
    syscall0 SYS_write
    mov     edi, 1
    syscall0 SYS_exit_group

.err_open_out:
    mov     edi, STDERR
    lea     rsi, [err_open_out_msg]
    mov     edx, err_open_out_len
    syscall0 SYS_write
    mov     edi, 1
    syscall0 SYS_exit_group

.err_mmap:
    mov     edi, STDERR
    lea     rsi, [err_mmap_msg]
    mov     edx, err_mmap_len
    syscall0 SYS_write
    mov     edi, 1
    syscall0 SYS_exit_group

.err_parse:
    mov     edi, STDERR
    lea     rsi, [err_parse_msg]
    mov     edx, err_parse_len
    syscall0 SYS_write
    mov     edi, 1
    syscall0 SYS_exit_group

; ---- mmap_alloc ----------------------------------------------------------
; void *mmap_alloc(size_t size);
;   Anonymous private rw mapping.  Returns ptr on success, kernel error (>-4095)
;   on failure.  Caller checks `cmp rax, -4095; jae fail`.

mmap_alloc:
    mov     rsi, rdi
    xor     edi, edi
    mov     edx, PROT_READ | PROT_WRITE
    mov     r10d, MAP_PRIVATE | MAP_ANONYMOUS
    mov     r8, -1
    xor     r9, r9
    syscall0 SYS_mmap
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
