; trace.inc — per-component cycle-level tracer.
;
; Pattern:
;   TRACE_TSC scratch            ; reg or mem — saves current TSC
;   ... do phase work ...
;   TRACE_PHASE_SUM sum_lbl, scratch       ; just accumulate sum
;   TRACE_PHASE_RING ring, sum, cursor, scratch ; sum + store at ring[cursor%N]
;   TRACE_BUMP cursor, dump_func           ; ++cursor; fires dump at DONE_AT
;
; Notes:
;   - All macros are single-thread (no atomics).
;   - rdtscp serializes the out-of-order core, so each macro costs ~30 cycles
;     on Haswell + a memory store.
;   - Ring buffers wrap (mod TRACE_N) until cursor reaches TRACE_DONE_AT,
;     after which TRACE_PHASE_RING skips and TRACE_BUMP no-ops.

%ifndef TRACE_INC
%define TRACE_INC

%define TRACE_N         4096            ; ring size (power of 2)

; TRACE_TSC dst — read full 64-bit TSC into dst (reg or mem64).
; Clobbers rax, rdx, rcx (rcx = aux_id from rdtscp, ignored).
%macro TRACE_TSC 1
    rdtscp
    shl     rdx, 32
    or      rax, rdx
    mov     %1, rax
%endmacro

; TRACE_PHASE_SUM sum_lbl, start
;   Adds (now - start) to *sum_lbl.  Clobbers rax, rdx, rcx.
%macro TRACE_PHASE_SUM 2
    rdtscp
    shl     rdx, 32
    or      rax, rdx
    sub     rax, %2
    add     [rel %1], rax
%endmacro

; TRACE_PHASE_RING ring_lbl, sum_lbl, cursor_lbl, start
;   Adds (now - start) to sum AND stores at ring[cursor & (N-1)].  Ring
;   wraps on each batch; does NOT bump cursor.  Clobbers rax, rdx, rcx, r11.
%macro TRACE_PHASE_RING 4
    rdtscp
    shl     rdx, 32
    or      rax, rdx
    sub     rax, %4
    add     [rel %2], rax
    mov     r11d, [rel %3]
    and     r11d, TRACE_N - 1
    lea     rcx, [rel %1]
    mov     [rcx + r11*8], rax
%endmacro

; TRACE_BUMP cursor_lbl, dump_func, period_pow2
;   ++cursor; calls dump_func every `period_pow2` events (must be power of 2).
;   File is overwritten on every dump, so the post-bench file contains the
;   most recent `period_pow2` samples mapped over the ring.
%macro TRACE_BUMP 3
    inc     dword [rel %1]
    mov     eax, [rel %1]
    test    eax, (%3 - 1)
    jnz     %%done
    call    %2
%%done:
%endmacro

; TRACE_COUNT counter_lbl
;   Cheap u64 inc (single-thread).
%macro TRACE_COUNT 1
    inc     qword [rel %1]
%endmacro

%endif ; TRACE_INC
