; Common nasm macros shared across modules.
;
; Conventions in this project:
;   - bits 64, default rel  (RIP-relative addressing for all symbol refs)
;   - System V AMD64 ABI on the boundary between "named functions"
;     (arg1..arg6 = rdi, rsi, rdx, rcx, r8, r9; ret = rax; xmm0 for floats)
;   - Inside functions, registers used freely (no callee-save guarantee)
;     unless a comment says otherwise.
;   - Stack 16-byte aligned before every CALL; entry to a leaf-or-call
;     function expects (rsp & 0xF) == 8 (return address pushed).

%ifndef MACROS_INC
%define MACROS_INC

; --- function prologue/epilogue ---------------------------------------------
; We do not use the standard SysV "push rbp; mov rbp, rsp" frame because most
; helpers are leaf and we want minimal overhead. Use FRAME/ENDFRAME only when
; the function calls other functions and needs a fixed local area.

%macro FRAME 1               ; %1 = local bytes (multiple of 16)
    push    rbp
    mov     rbp, rsp
    sub     rsp, %1
%endmacro

%macro ENDFRAME 0
    mov     rsp, rbp
    pop     rbp
%endmacro

; --- short jumps from condition codes --------------------------------------
; nasm shortcuts that read better in the source than raw setcc/jcc.

; --- alignment helpers ------------------------------------------------------

%macro ALIGN_PAGE 0
    align   4096
%endmacro

%macro ALIGN_CACHE 0
    align   64
%endmacro

; --- numeric constants ------------------------------------------------------

%define INT16_MAX 32767
%define INT16_MIN -32768
%define INT32_MAX 2147483647
%define INT64_MAX 0x7FFFFFFFFFFFFFFF

; --- project constants -----------------------------------------------------

%define N_DIMS        14
%define N_CLUSTERS    2048
%define K_NEIGHBORS   5

; ---- Partitioned index --------------------------------------------------
; The reference set is split into 4 sub-indices by (unknown_merchant,
; has_last_tx).  Top-5 nearest neighbors share both tags in 100% of
; 5000 sampled queries (i16-quantized), so partition routing is
; detection-safe.  Each partition is built as a separate index.bin file
; with its own K (sized proportional to partition vector count).  The
; server loads all 4 at startup and routes queries by tag at runtime.
%define N_PARTITIONS  4
; Initial probe budget; if top-5 label count falls in [NPROBE_REPAIR_MIN,
; NPROBE_REPAIR_MAX] (ambiguous), the probe loop extends to N_CLUSTERS so
; the lb-prune can run a full sweep.  The repair phase continues across the full sweep.
%define NPROBE_INITIAL     16
%define NPROBE_REPAIR_MIN  1
%define NPROBE_REPAIR_MAX  4
%define SCALE         10000
%define N_PAIRS       7
%define BBOX_LANES    16
%define IDX_BITS      22
%define CID_BITS      12
%define CID_MASK      0xFFF

%endif ; MACROS_INC
