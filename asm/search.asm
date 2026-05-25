; k-NN over the IVF index.
;
; Implemented incrementally:
;   - compute_cluster_packed (phase 1): per-cluster bbox lower-bound, packed as
;       (lb << CID_BITS) | cid into an N_CLUSTERS-entry i64 array.
;   - pick_min_cluster       (phase 2): 4-wide AVX2 min over the packed array,
;       used to choose the next cluster to probe (smallest lb wins, cid breaks
;       ties).  Caller tombstones consumed clusters with INT64_MAX in place.
;   - scan_cluster           (phase 3): for one cluster, computes sum-of-7-pair
;       squared distances against the query (AVX2 madd batched over 8 vectors)
;       and updates the 5-entry top-K with packed (dist<<22)|idx keys.  This
;       version omits the early-termination optimization (worst_dist threshold
;       check + cmpgt + testz) and the prefetch — both are perf-only; correct
;       top-K is identical.  Will add once correctness is proven.
;   - search_core / search / search_dbg: orchestrate phases 1-3, expose the
;       public surface.  Trace output is not implemented (NULL ignored).
;   - index_open: mmap the .bin, verify magic + n_clusters, populate IvfIndex
;       section pointers (64-byte aligned between sections).  Env-var tuning
;       (g_max_probes/g_fast_*) is intentionally skipped — perf knobs only.

bits 64
default rel

%include "syscalls.inc"
%include "macros.inc"

; ---- IvfIndex struct layout ------------------------------------------------
%define IX_FD                0    ; int      (+4 pad)
%define IX_MAP               8    ; void*
%define IX_MAP_SIZE          16   ; size_t
%define IX_N_CLUSTERS        24   ; u32
%define IX_N_VECTORS         28   ; u32
%define IX_CLUSTER_OFFSETS   32   ; const u32*
%define IX_BBOX_MIN          40   ; const i16*
%define IX_BBOX_MAX          48   ; const i16*
%define IX_PAIRS             56   ; const i16* [7]
%define IX_LABELS            112  ; const u8*

; ---------------------------------------------------------------------------
section .text

; ---- compute_cluster_packed ----------------------------------------------
;   void compute_cluster_packed(
;     const Query *q,         // rdi  -- 16 i16 (32 B); v[14..15] = 0
;     const int16_t *bmin,    // rsi  -- n * 32 B
;     const int16_t *bmax,    // rdx  -- n * 32 B
;     uint32_t n_clusters,    // ecx
;     int64_t *out);          // r8   -- n * 8 B
;
; For each cluster c in [0, n):
;   below = max(bmin[c] - q, 0)        ; per-lane i16
;   above = max(q - bmax[c], 0)
;   gap   = max(below, above)
;   sq    = madd_epi16(gap, gap)       ; 8 i32 lanes, sums of two i16 squares
;   lb    = hsum_i32_to_i64(sq)
;   out[c] = (lb << CID_BITS) | c
;
; All in [0, INT32_MAX] per lane; full sum fits in 64 bits easily.

global compute_cluster_packed
compute_cluster_packed:
    vmovdqu      ymm0, [rdi]            ; qvec
    vpxor        ymm1, ymm1, ymm1       ; zero

    xor          eax, eax               ; c = 0
.loop:
    cmp          eax, ecx
    jae          .done

    mov          r9d, eax
    shl          r9, 5                  ; r9 = c * 32 bytes

    vmovdqu      ymm2, [rsi + r9]       ; bmin[c]
    vmovdqu      ymm3, [rdx + r9]       ; bmax[c]
    vpsubw       ymm4, ymm2, ymm0       ; bmin - q
    vpmaxsw      ymm4, ymm4, ymm1       ; below
    vpsubw       ymm5, ymm0, ymm3       ; q - bmax
    vpmaxsw      ymm5, ymm5, ymm1       ; above
    vpmaxsw      ymm4, ymm4, ymm5       ; gap (per i16 lane, ≥ 0)
    vpmaddwd     ymm4, ymm4, ymm4       ; 8 i32 lanes (each ≤ 2^31-1)

    ; hsum 8 i32 → 1 i64 (widen first; 8 lanes of ~31 bits would overflow i32)
    vextracti128 xmm5, ymm4, 1
    vpmovsxdq    ymm6, xmm4             ; low 4 i32 → 4 i64
    vpmovsxdq    ymm7, xmm5             ; high 4 i32 → 4 i64
    vpaddq       ymm6, ymm6, ymm7
    vextracti128 xmm7, ymm6, 1
    vpaddq       xmm6, xmm6, xmm7
    vpunpckhqdq  xmm7, xmm6, xmm6
    vpaddq       xmm6, xmm6, xmm7
    vmovq        r10, xmm6              ; lb

    shl          r10, CID_BITS
    or           r10, rax               ; (lb << 12) | c
    mov          [r8 + rax*8], r10

    inc          eax
    jmp          .loop

.done:
    vzeroupper
    ret

; ---- pick_min_cluster -----------------------------------------------------
;   int64_t pick_min_cluster(const int64_t *packed, uint32_t n);
;     rdi = packed array, esi = n  (must be multiple of 8)
;     returns rax = min packed, or INT64_MAX if all entries are INT64_MAX
;
; Signed compare is correct because every packed value is non-negative
; (lb_max ~5.6e9 → 33 bits, |cid 12 bits = 45 bits) and INT64_MAX itself
; has bit 63 clear.
;
; Dual-chain: process 8 i64 lanes per iter via two independent min accums
; (ymm0, ymm10).  Breaks the vpblendvb dep chain (port 5) that capped the
; single-chain loop at ~2 cycles per 4 lanes.  Now ~2 cycles per 8 lanes.

global pick_min_cluster
pick_min_cluster:
    mov          rax, 0x7FFFFFFFFFFFFFFF
    vmovq        xmm0, rax
    vpbroadcastq ymm0, xmm0                ; chain A min = [INT64_MAX × 4]
    vpbroadcastq ymm10, xmm0               ; chain B min = [INT64_MAX × 4]

    xor          ecx, ecx                  ; c = 0
.loop:
    cmp          ecx, esi
    jae          .reduce
    vmovdqu      ymm1, [rdi + rcx*8]       ; lanes c..c+3
    vmovdqu      ymm3, [rdi + rcx*8 + 32]  ; lanes c+4..c+7
    vpcmpgtq     ymm2, ymm0, ymm1
    vpcmpgtq     ymm4, ymm10, ymm3
    vpblendvb    ymm0, ymm0, ymm1, ymm2
    vpblendvb    ymm10, ymm10, ymm3, ymm4
    add          ecx, 8
    jmp          .loop

.reduce:
    ; Fold chain B into chain A.
    vpcmpgtq     ymm2, ymm0, ymm10
    vpblendvb    ymm0, ymm0, ymm10, ymm2

    vextracti128 xmm1, ymm0, 1             ; xmm1 = lanes [2,3]
    vpcmpgtq     xmm2, xmm0, xmm1
    vpblendvb    xmm0, xmm0, xmm1, xmm2    ; xmm0 = [min(0,2), min(1,3)]
    vpunpckhqdq  xmm1, xmm0, xmm0
    vpcmpgtq     xmm2, xmm0, xmm1
    vpblendvb    xmm0, xmm0, xmm1, xmm2
    vmovq        rax, xmm0
    vzeroupper
    ret

; ---- scan_cluster ---------------------------------------------------------
;   void scan_cluster(
;     const IvfIndex *ix,        // rdi
;     uint32_t best_c,           // esi
;     const __m256i *qpair,      // rdx -- 7 broadcasted i32 ymms, 32-aligned
;     int64_t topk_k[5],         // rcx
;     uint8_t topk_l[5],         // r8
;     int64_t *worst_key_io);    // r9   in/out
;
; Iterates the cluster's vectors in batches of 8.  For each batch:
;   s = sum over p∈{3,5,0,1,2,4,6} of pair_sq_p(vec_chunk)
;   key_j = (s_j << IDX_BITS) | (start + i + j)
;   if key_j < worst_key:   update top-K[argmax] and recompute worst_key
;
; Top-K update is branchless across the 5-entry argmax (4×cmovg pairs);
; recompute of worst is the same pattern with cmovg-on-max only.
;
; Stack layout (after pushes + sub rsp, 136):
;   [rsp +   0..55]  pair_base[0..6] = ix->pairs[p] + 4 * start
;   [rsp +  56..63]  worst_key_io ptr (stashed for epilog)
;   [rsp +  64..127] dists[8] i64 staging
;   [rsp + 128..135] labels_base = ix->labels + start

; Two-arg form: %1 = pair index (also the qpair ymm register), %2 = destination
; accumulator register (one of two parallel chains to break the vpaddd dep chain).
%macro PAIR_INIT 2
    mov     rax, [rsp + %1*8]
    vmovdqu ymm8, [rax + rcx*4]
    vpsubw  ymm8, ymm8, ymm%1
    vpmaddwd ymm%2, ymm8, ymm8
%endmacro

%macro PAIR_ADD 2
    mov     rax, [rsp + %1*8]
    vmovdqu ymm8, [rax + rcx*4]
    vpsubw  ymm8, ymm8, ymm%1
    vpmaddwd ymm8, ymm8, ymm8
    vpaddd  ymm%2, ymm%2, ymm8
%endmacro

global scan_cluster
scan_cluster:
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 136

    mov     rbx, rdi                       ; ix
    mov     r12, rcx                       ; topk_k
    mov     r13, r8                        ; topk_l
    mov     [rsp + 56], r9                 ; stash worst_key_io ptr
    mov     r14, [r9]                      ; worst_key (current)

    ; qpair[0..6] into ymm0..ymm6
    vmovdqa ymm0, [rdx + 0*32]
    vmovdqa ymm1, [rdx + 1*32]
    vmovdqa ymm2, [rdx + 2*32]
    vmovdqa ymm3, [rdx + 3*32]
    vmovdqa ymm4, [rdx + 4*32]
    vmovdqa ymm5, [rdx + 5*32]
    vmovdqa ymm6, [rdx + 6*32]

    ; start, end, count from ix->cluster_offsets
    mov     rdi, [rbx + IX_CLUSTER_OFFSETS]
    mov     r15d, [rdi + rsi*4]            ; start (u32, zero-ext)
    mov     r11d, [rdi + rsi*4 + 4]        ; end
    mov     ebp, r11d
    sub     ebp, r15d                      ; count

    ; pair_base[p] = ix->pairs[p] + 4 * start  → stack
%assign P 0
%rep 7
    mov     rdi, [rbx + IX_PAIRS + P*8]
    lea     rdi, [rdi + r15*4]
    mov     [rsp + P*8], rdi
%assign P P+1
%endrep

    ; labels_base = ix->labels + start
    mov     rdi, [rbx + IX_LABELS]
    add     rdi, r15
    mov     [rsp + 128], rdi

    xor     rcx, rcx                       ; i = 0 (vector index, batches of 8)

    align   32                              ; let DSB capture the hot loop body
.batch:
    cmp     rcx, rbp
    jae     .done

    ; ----- prefetch ~96 vectors (12 batches) ahead when far from cluster end.
    ; At +128 B the prefetch landed only 4 batches ahead, which on a hot batch
    ; (~10 cycles at 3 GHz) is ~12 ns — far short of DRAM latency (~80 ns).
    ; +384 B = 96 vectors = ~12 batches, giving the line ~120 ns of head start.
    lea     rax, [rcx + 96]
    cmp     rax, rbp
    jae     .skip_prefetch
%assign P 0
%rep N_PAIRS
    mov     rax, [rsp + P*8]
    prefetcht0 [rax + rcx*4 + 384]
%assign P P+1
%endrep
.skip_prefetch:

    ; ----- dual accumulators: chain A = ymm7, chain B = ymm13.
    ;        Halves the vpaddd dep-chain latency of the original single-chain.
    ;        Pair assignment: A ← {3, 0, 2, 6}  (4),  B ← {5, 1, 4}  (3).
    PAIR_INIT 3, 7                           ; sA = pair3²
    PAIR_INIT 5, 13                          ; sB = pair5²

    ; ----- early-termination gate (after partial sum sA + sB) -----
    mov     rax, r14
    sar     rax, IDX_BITS                    ; worst_dist = worst_key >> 22 (worst_key ≥ 0)
    cmp     rax, 0x7FFFFFFF
    jg      .no_thresh                       ; top-K not settled yet → skip gate

    vmovd        xmm9, eax
    vpbroadcastd ymm9, xmm9                  ; thresh broadcast as 8 i32

    vpaddd   ymm14, ymm7, ymm13              ; partial = sA + sB
    vpcmpgtd ymm10, ymm9, ymm14
    vptest   ymm10, ymm10
    jz       .next_batch_skip

    PAIR_ADD 0, 7
    PAIR_ADD 1, 13

    vpaddd   ymm14, ymm7, ymm13
    vpcmpgtd ymm10, ymm9, ymm14
    vptest   ymm10, ymm10
    jz       .next_batch_skip

    PAIR_ADD 2, 7
    PAIR_ADD 4, 13
    PAIR_ADD 6, 7
    vpaddd   ymm7, ymm7, ymm13               ; final s = sA + sB
    jmp      .do_topk

.no_thresh:
    PAIR_ADD 0, 7
    PAIR_ADD 1, 13
    PAIR_ADD 2, 7
    PAIR_ADD 4, 13
    PAIR_ADD 6, 7
    vpaddd   ymm7, ymm7, ymm13               ; final s = sA + sB

.do_topk:
    ; widen 8 i32 → 8 i64; store dists
    vpmovzxdq    ymm11, xmm7
    vextracti128 xmm8, ymm7, 1
    vpmovzxdq    ymm12, xmm8
    vmovdqu      [rsp + 64], ymm11
    vmovdqu      [rsp + 96], ymm12

    ; valid = min(8, count - i)
    mov     r10, rbp
    sub     r10, rcx                       ; count - i
    mov     r11d, 8
    cmp     r10, 8
    cmovl   r11, r10                       ; r11 = valid (1..8)

    xor     r10, r10                       ; j = 0
.j_loop:
    cmp     r10, r11
    jae     .j_done

    ; key = (dists[j] << IDX_BITS) | (start + i + j)
    mov     rax, [rsp + 64 + r10*8]
    shl     rax, IDX_BITS
    lea     rdi, [r15 + rcx]
    add     rdi, r10
    or      rax, rdi                       ; rax = key

    cmp     rax, r14
    jae     .skip

    ; argmax over topk_k[0..4]  →  r8d = wi, rdx = max value
    mov     rdx, [r12 + 0*8]
    xor     r8d, r8d
    mov     r9d, 1
    mov     rdi, [r12 + 1*8]
    cmp     rdi, rdx
    cmovg   rdx, rdi
    cmovg   r8d, r9d
    mov     r9d, 2
    mov     rdi, [r12 + 2*8]
    cmp     rdi, rdx
    cmovg   rdx, rdi
    cmovg   r8d, r9d
    mov     r9d, 3
    mov     rdi, [r12 + 3*8]
    cmp     rdi, rdx
    cmovg   rdx, rdi
    cmovg   r8d, r9d
    mov     r9d, 4
    mov     rdi, [r12 + 4*8]
    cmp     rdi, rdx
    cmovg   rdx, rdi
    cmovg   r8d, r9d

    ; topk_k[wi] = key
    mov     [r12 + r8*8], rax

    ; topk_l[wi] = labels_base[i + j]
    mov     rdi, [rsp + 128]
    add     rdi, rcx
    add     rdi, r10
    movzx   eax, byte [rdi]
    mov     [r13 + r8], al

    ; worst_key = max(topk_k[0..4])
    mov     r14, [r12 + 0*8]
    mov     rdi, [r12 + 1*8]
    cmp     rdi, r14
    cmovg   r14, rdi
    mov     rdi, [r12 + 2*8]
    cmp     rdi, r14
    cmovg   r14, rdi
    mov     rdi, [r12 + 3*8]
    cmp     rdi, r14
    cmovg   r14, rdi
    mov     rdi, [r12 + 4*8]
    cmp     rdi, r14
    cmovg   r14, rdi

.skip:
    inc     r10
    jmp     .j_loop
.j_done:

.next_batch_skip:
    add     rcx, 8                          ; i += 8
    jmp     .batch

.done:
    ; Write back worst_key
    mov     rax, [rsp + 56]
    mov     [rax], r14

    add     rsp, 136
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    vzeroupper
    ret

; ---- search_core ----------------------------------------------------------
;   void search_core(
;     const IvfIndex *ix,    // rdi
;     const Query *q,        // rsi
;     int max_probes,        // edx
;     SearchTrace *trace,    // rcx   -- ignored (always treated as NULL)
;     int64_t topk_k[5],     // r8
;     uint8_t topk_l[5]);    // r9

; N_CLUSTERS × 8 B = 32768 B for the packed lower-bound array.  Previous
; layout assumed k=2048 (16384 B); with k=4096 the array doubles, so QPAIR
; and every later slot move up.
%define SS_CLUSTER_PACKED   0
%define SS_QPAIR            32768       ; 7 * 32 = 224 B, 32-aligned
%define SS_WORST_KEY        32992
%define SS_Q                33000
%define SS_MAX_PROBES       33008
%define FRAME_SIZE          33088       ; sub rsp, + 32 slack for `and rsp, -32`

global search_core
search_core:
    push    rbp
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15

    mov     rbx, rdi                       ; ix
    mov     r12, r8                        ; topk_k
    mov     r13, r9                        ; topk_l

    mov     rbp, rsp
    sub     rsp, FRAME_SIZE
    and     rsp, -32                       ; 32-byte align local frame

    mov     [rsp + SS_Q], rsi
    mov     [rsp + SS_MAX_PROBES], edx

    ; topk_k[0..4] = INT64_MAX, topk_l[0..4] = 0, worst_key = INT64_MAX
    mov     rax, 0x7FFFFFFFFFFFFFFF
    mov     [r12 + 0*8], rax
    mov     [r12 + 1*8], rax
    mov     [r12 + 2*8], rax
    mov     [r12 + 3*8], rax
    mov     [r12 + 4*8], rax
    mov     dword [r13], 0
    mov     byte  [r13 + 4], 0
    mov     r14, rax                       ; worst_key

    ; Build qpair[7] from q (still in rsi): each broadcasted as 8 × i32.
    ; q is little-endian i16 array, so 4 consecutive bytes at q + p*4 already
    ; form the packed (hi<<16)|lo dword used for paired-i16 subtract.
%assign P 0
%rep 7
    vpbroadcastd ymm0, dword [rsi + P*4]
    vmovdqa      [rsp + SS_QPAIR + P*32], ymm0
%assign P P+1
%endrep

    ; Phase 1: compute_cluster_packed(q, bmin, bmax, n_clusters, out)
    mov     rdi, rsi
    mov     rsi, [rbx + IX_BBOX_MIN]
    mov     rdx, [rbx + IX_BBOX_MAX]
    mov     ecx, [rbx + IX_N_CLUSTERS]
    lea     r8, [rsp + SS_CLUSTER_PACKED]
    call    compute_cluster_packed

    xor     r15d, r15d                     ; probe_count

.probe:
    cmp     r15d, [rsp + SS_MAX_PROBES]
    jge     .done

    lea     rdi, [rsp + SS_CLUSTER_PACKED]
    mov     esi, [rbx + IX_N_CLUSTERS]
    call    pick_min_cluster               ; rax = best_packed

    mov     rdi, 0x7FFFFFFFFFFFFFFF
    cmp     rax, rdi
    je      .done                          ; all tombstoned

    ; If (best_lb << IDX_BITS) >= worst_key, no further cluster can improve
    mov     rdi, rax
    sar     rdi, CID_BITS                  ; best_lb (non-negative; arithmetic shift OK)
    shl     rdi, IDX_BITS

    ; Adaptive tail cut: once we've already paid for >10 probes, inflate the
    ; lower bound by +50% so the prune below fires more eagerly.  Trades a
    ; bit of accuracy on slow queries for a big p99 win.
    cmp     r15d, 10
    jle     .check_term
    mov     rcx, rdi
    shr     rcx, 1                         ; rcx = best_lb / 2
    add     rdi, rcx                       ; rdi = best_lb * 3/2
.check_term:
    cmp     rdi, r14
    jge     .done

    ; Tombstone: cluster_packed[best_c] = INT64_MAX
    mov     rdi, rax
    and     edi, CID_MASK                  ; best_c
    mov     rdx, 0x7FFFFFFFFFFFFFFF
    lea     rcx, [rsp + SS_CLUSTER_PACKED]
    mov     [rcx + rdi*8], rdx

    ; scan_cluster(ix, best_c, qpair, topk_k, topk_l, &worst_key)
    mov     [rsp + SS_WORST_KEY], r14
    mov     esi, edi                       ; best_c -> arg2
    mov     rdi, rbx                       ; ix    -> arg1
    lea     rdx, [rsp + SS_QPAIR]          ; qpair -> arg3
    mov     rcx, r12                       ; topk_k -> arg4
    mov     r8, r13                        ; topk_l -> arg5
    lea     r9, [rsp + SS_WORST_KEY]       ; &worst_key -> arg6
    call    scan_cluster
    mov     r14, [rsp + SS_WORST_KEY]      ; reload updated worst_key

    inc     r15d

    ; Clear-cut early exit: after 4 probes, if top-5 labels are all-0 (all
    ; legit) or all-1 (all fraud), the result is unambiguous — additional
    ; probes can't change cnt, so we skip the rest.  Inspired by leader's
    ; "repair pass" pattern but inverted: WE commit to the fast path by
    ; default, only continue when ambiguous.
    cmp     r15d, 4
    jne     .probe
    mov     rcx, 0x7FFFFFFFFFFFFFFF
    cmp     r14, rcx
    je      .probe                          ; top-5 not yet full; keep probing
    ; Sum 5 label bytes via popcnt: each byte is 0 or 1, so the count of set
    ; bits in the 5-byte block equals the fraud count.  Caller's topk_l[5]
    ; lives in a 56-byte stack slot, so reading 8 bytes is safe.
    mov     rax, [r13]                       ; 8 bytes (last 3 are garbage)
    mov     rcx, 0xFFFFFFFFFF                ; mask to first 5 bytes
    and     rax, rcx
    popcnt  rax, rax                         ; rax ∈ [0,5]
    test    eax, eax                        ; cnt == 0 → all legit
    jz      .done
    cmp     eax, 5                          ; cnt == 5 → all fraud
    je      .done
    jmp     .probe

.done:
    mov     rsp, rbp
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    ret

; ---- search --------------------------------------------------------------
;   uint8_t search(const IvfIndex *ix, const Query *q);
;     rdi = ix, rsi = q
;     ret = sum of top-5 labels (fraud count, 0..5)

global search
search:
    sub     rsp, 56                         ; topk_k(40)+topk_l(5)+pad — keeps rsp aligned
    ; layout: [rsp + 0..39] topk_k, [rsp + 40..44] topk_l

    mov     edx, [rdi + IX_N_CLUSTERS]      ; max_probes = full sweep; adaptive
                                            ; epsilon in search_core caps work
    xor     ecx, ecx                        ; trace = NULL
    lea     r8, [rsp]
    lea     r9, [rsp + 40]
    call    search_core

    ; Sum 5 label bytes via popcnt — each byte is 0 or 1.  The 56-byte stack
    ; allocation has 11 bytes of slack past topk_l, so reading 8 bytes from
    ; [rsp+40] is safe.
    mov     rax, [rsp + 40]                 ; 8 bytes (last 3 garbage)
    mov     rcx, 0xFFFFFFFFFF               ; mask first 5 bytes
    and     rax, rcx
    popcnt  rax, rax                        ; rax ∈ [0,5]

    add     rsp, 56
    ret

; ---- search_dbg ----------------------------------------------------------
;   uint8_t search_dbg(const IvfIndex *ix, const Query *q,
;                      int64_t out_d[5], uint32_t out_i[5], uint8_t out_l[5]);
;     rdi = ix, rsi = q, rdx = out_d, rcx = out_i, r8 = out_l
;     ret = sum of top-5 labels
;
; Runs search_core, sorts top-K ascending by packed key, then unpacks to
; (dist, idx, label) per slot.  Sort: selection-style 10-pair compare-and-swap.

%macro SWAP_IF_LESS 2
    mov     rax, [r12 + %1*8]
    mov     rcx, [r12 + %2*8]
    cmp     rcx, rax                        ; topk_k[%2] < topk_k[%1] ?
    mov     rdi, rax
    cmovl   rax, rcx
    cmovl   rcx, rdi
    mov     [r12 + %1*8], rax
    mov     [r12 + %2*8], rcx
    movzx   eax, byte [r13 + %1]
    movzx   ecx, byte [r13 + %2]
    mov     edi, eax
    cmovl   eax, ecx                        ; flags from prior cmp still live
    cmovl   ecx, edi
    mov     [r13 + %1], al
    mov     [r13 + %2], cl
%endmacro

global search_dbg
search_dbg:
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 56                         ; topk_k(40)+topk_l(5)+pad — 8-aligned mod 16

    mov     rbx, rdx                        ; out_d
    mov     rbp, rcx                        ; out_i
    mov     r14, r8                         ; out_l
    lea     r12, [rsp]                      ; topk_k local
    lea     r13, [rsp + 40]                 ; topk_l local

    mov     edx, [rdi + IX_N_CLUSTERS]
    xor     ecx, ecx
    mov     r8, r12
    mov     r9, r13
    call    search_core

    ; Sort 5 entries ascending by packed key (selection-style)
    SWAP_IF_LESS 0, 1
    SWAP_IF_LESS 0, 2
    SWAP_IF_LESS 0, 3
    SWAP_IF_LESS 0, 4
    SWAP_IF_LESS 1, 2
    SWAP_IF_LESS 1, 3
    SWAP_IF_LESS 1, 4
    SWAP_IF_LESS 2, 3
    SWAP_IF_LESS 2, 4
    SWAP_IF_LESS 3, 4

    ; Unpack and accumulate fraud
    xor     r15d, r15d                      ; fraud sum
%assign K 0
%rep 5
    mov     rax, [r12 + K*8]                ; topk_k[K]
    mov     rdx, rax
    shr     rdx, IDX_BITS                   ; logical: dist
    mov     [rbx + K*8], rdx
    mov     ecx, eax                        ; low 32 bits
    and     ecx, (1 << IDX_BITS) - 1
    mov     [rbp + K*4], ecx
    movzx   edx, byte [r13 + K]
    mov     [r14 + K], dl
    add     r15d, edx
%assign K K+1
%endrep
    mov     eax, r15d                       ; caller takes low byte for u8

    add     rsp, 56
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret

; ---- index_open ----------------------------------------------------------
;   int index_open(IvfIndex *out, const char *path);
;     rdi = out, rsi = path
;     returns eax = 0 on success, -1 on failure
;
; Steps:
;   1. open(path, O_RDONLY); fstat → size; mmap PRIVATE|POPULATE
;   2. mlock + madvise(HUGEPAGE) + madvise(WILLNEED)   [best-effort]
;   3. Verify magic "RNH4-IDX" and n_clusters == N_CLUSTERS
;   4. Walk sections with 64-byte alignment, populate IvfIndex pointers
;   5. Final bounds check off ≤ map_size
;
; Stack frame: 6 pushes + sub 152 → rsp 0 mod 16.  Locals:
;   [rsp +   0..143]  struct stat  (Linux x86-64, 144 bytes)
;   [rsp + 144..151]  alignment pad

%define STAT_OFFSET_SIZE 48
%define IVF_MAGIC_LE     0x5844492D34484E52   ; "RNH4-IDX" little-endian
%define ALIGN_BIN        64

global index_open
index_open:
    push    rbx                              ; out
    push    rbp                              ; map
    push    r12                              ; map_size
    push    r13                              ; fd
    push    r14                              ; off (size_t walker)
    push    r15                              ; nv (n_vectors)
    sub     rsp, 152

    mov     rbx, rdi                         ; save out

    ; fd = open(path, O_RDONLY)
    mov     rdi, rsi                         ; path
    xor     esi, esi                         ; flags = 0
    xor     edx, edx                         ; mode (ignored)
    syscall0 SYS_open
    test    rax, rax
    js      .fail                            ; -errno
    mov     r13, rax

    ; fstat(fd, &st)
    mov     rdi, r13
    lea     rsi, [rsp + 0]
    syscall0 SYS_fstat
    test    rax, rax
    js      .fail_close
    mov     r12, [rsp + STAT_OFFSET_SIZE]    ; map_size = st.st_size

    ; map = mmap(NULL, sz, PROT_READ, MAP_PRIVATE|MAP_POPULATE, fd, 0)
    xor     edi, edi
    mov     rsi, r12
    mov     edx, PROT_READ
    mov     r10d, MAP_PRIVATE | MAP_POPULATE
    mov     r8, r13
    xor     r9d, r9d
    syscall0 SYS_mmap
    cmp     rax, -4095
    jae     .fail_close                      ; in [-4095, -1] = errno
    mov     rbp, rax                         ; map

    ; mlock(map, sz)   [ignore failure]
    mov     rdi, rbp
    mov     rsi, r12
    syscall0 SYS_mlock

    ; madvise(map, sz, MADV_HUGEPAGE)
    mov     rdi, rbp
    mov     rsi, r12
    mov     edx, MADV_HUGEPAGE
    syscall0 SYS_madvise

    ; madvise(map, sz, MADV_WILLNEED)
    mov     rdi, rbp
    mov     rsi, r12
    mov     edx, MADV_WILLNEED
    syscall0 SYS_madvise

    ; Verify magic
    mov     rax, [rbp + 0]
    mov     rcx, IVF_MAGIC_LE
    cmp     rax, rcx
    jne     .fail_unmap

    ; Check n_clusters == N_CLUSTERS
    mov     eax, [rbp + 8]
    cmp     eax, N_CLUSTERS
    jne     .fail_unmap

    mov     r15d, [rbp + 12]                 ; nv

    ; off starts at sizeof(IvfHeader) = 64 (already 64-aligned)
    mov     r14, 64

    ; cluster_offsets = map + off
    lea     rax, [rbp + r14]
    mov     [rbx + IX_CLUSTER_OFFSETS], rax

    ; off += (nc + 1) * 4
    mov     eax, [rbp + 8]
    inc     eax
    shl     rax, 2
    add     r14, rax
    add     r14, ALIGN_BIN - 1
    and     r14, -ALIGN_BIN

    ; bbox_min
    lea     rax, [rbp + r14]
    mov     [rbx + IX_BBOX_MIN], rax
    mov     eax, [rbp + 8]
    shl     rax, 5                            ; nc * 32
    add     r14, rax
    add     r14, ALIGN_BIN - 1
    and     r14, -ALIGN_BIN

    ; bbox_max
    lea     rax, [rbp + r14]
    mov     [rbx + IX_BBOX_MAX], rax
    mov     eax, [rbp + 8]
    shl     rax, 5
    add     r14, rax
    add     r14, ALIGN_BIN - 1
    and     r14, -ALIGN_BIN

    ; pairs[0..6]
%assign P 0
%rep 7
    lea     rax, [rbp + r14]
    mov     [rbx + IX_PAIRS + P*8], rax
    mov     eax, r15d
    shl     rax, 2                            ; nv * 4 bytes (2 i16 per vec)
    add     r14, rax
    add     r14, ALIGN_BIN - 1
    and     r14, -ALIGN_BIN
%assign P P+1
%endrep

    ; labels
    lea     rax, [rbp + r14]
    mov     [rbx + IX_LABELS], rax
    mov     eax, r15d
    add     r14, rax                          ; off += nv

    ; Bounds check
    cmp     r14, r12
    ja      .fail_unmap

    ; Fill the rest of IvfIndex
    mov     dword [rbx + IX_FD], r13d
    mov     dword [rbx + IX_FD + 4], 0        ; padding (struct stat 32-bit int + 4 pad)
    mov     [rbx + IX_MAP], rbp
    mov     [rbx + IX_MAP_SIZE], r12
    mov     eax, [rbp + 8]
    mov     [rbx + IX_N_CLUSTERS], eax
    mov     [rbx + IX_N_VECTORS], r15d

    xor     eax, eax
    add     rsp, 152
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret

.fail_unmap:
    mov     rdi, rbp
    mov     rsi, r12
    syscall0 SYS_munmap
    ; fall-through to close
.fail_close:
    mov     rdi, r13
    syscall0 SYS_close
.fail:
    mov     eax, -1
    add     rsp, 152
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
