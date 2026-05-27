# rinha-asm

Submission for [Rinha de Backend 2026](https://github.com/zanfranceschi/rinha-de-backend-2026) written in **pure x86-64 NASM assembly** — no libc, no runtime, no framework, no managed allocator.  Statically linked against bare Linux syscalls.

## Architecture

```
client → :9999 (TCP) → asm_lb ──SCM_RIGHTS──▶ asm_server (×2) ──TCP──▶ client
                          │                        │
                          ▼                        ▼
                    io_uring multishot         io_uring multishot recv
                    accept + sendmsg(fd)       + provided buffer ring
                                               + handle_request inline
```

- **`asm_lb`** — TCP listener.  io_uring multishot accept; for each accepted client fd, sets `TCP_NODELAY` + `TCP_QUICKACK` and submits `sendmsg(SCM_RIGHTS)` hardlinked to `close` to one of the API workers over a Unix-domain socket.  Round-robin.  Zero byte-proxying after the handoff — responses go directly from the API back to the client over TCP.
- **`asm_server`** — API worker.  Receives client fds from the LB via multishot `recvmsg` (`MSG_CMSG_CLOEXEC`), then runs the full HTTP pipeline via io_uring multishot recv with a provided buffer ring: `recv → http_frame → parse_request (JSON) → vectorize → IVF k-NN search → emit pre-rendered HTTP response → send`.  Single-threaded event loop.  NAPI busy-poll registered on the ring.
- **`asm_build_index`** — offline tool.  Parses the `references.json.gz` corpus, runs k-means clustering per partition (4 partitions × 2048 clusters, 14 dims, 20 iters), builds the IVF index with per-cluster axis-aligned bbox lower-bounds packed as SoA pair arrays, writes the binary index files.

## Fraud-detection model

IVF k-NN, K = 5 neighbours, partitioned by domain tag.  Pre-classify each request by the 2-bit tag `(unknown_merchant << 1) | has_last_tx` and search only the matching of four partitioned indices (3 M reference vectors total, split unevenly across partitions by their natural occurrence in the corpus).

Within a partition:
- 14-dim `int16` quantized query (vectorize quantizes 14 normalized floats to `[-10000, 10000]`).
- Phase 1: per-cluster bbox lower-bound packed as `(lb << CID_BITS) | cid` into an `N_CLUSTERS`-entry `i64` array (`compute_cluster_packed`, 8 clusters / ymm iter, **dual-chain accumulators** across the 7 pair groups).
- Phase 2: pick next probe via `pick_min_cluster` (dual-chain AVX2 `vpcmpgtq` + `vpblendvb` min reduction).
- Phase 3: `scan_cluster` exhaustively over the cluster's vectors, 8 vectors per ymm iter with dual-chain accumulators, AVX2 early-termination gate (`vpminud` saturated against `vpcmpgtd`).
- Top-K is a branchless packed `(distance << IDX_BITS) | reference_idx` keyed array of 5.
- Repair pattern: after `NPROBE_INITIAL = 12` probes, unambiguous fraud counts (0 or 5) return; ambiguous counts ([1, 4]) extend the probe budget to the full cluster set.

AVX2 + BMI2 + FMA3 SIMD throughout — `vpmaddwd` for squared L2, `vpcmpgtq` for cluster min selection, `vpmaxsw` / `vpmaddwd` for bbox gap, `vfmadd213sd` in `vectorize.asm` for the post-clamp `* scale + half` round, `bzhi` / `tzcnt` in JSON parsing.

## Repo layout

```
asm/
├── server.asm         API worker: io_uring event loop + HTTP framing + warm-up
├── lb.asm             Load balancer: io_uring multishot accept + SCM_RIGHTS handoff
├── build_index.asm    Offline index builder: parse_refs + kmeans + bbox_pack + write_index_bin
├── parse.asm          JSON parser (skip_ws + parse_number with FMA + parse_iso8601 + key_eq via XOR/bzhi)
├── vectorize.asm      Request → 14-dim i16 Query  (FMA3-fused clamp01 + quantization)
├── search.asm         IVF k-NN  (compute_cluster_packed + pick_min_cluster + scan_cluster + search_core)
├── mcc.asm            MCC risk lookup (AVX2 broadcast-compare against 10 overrides + default)
├── uring.asm/uring.inc  io_uring helpers (registered files, SINGLE_ISSUER + DEFER_TASKRUN + SUBMIT_ALL, NAPI)
├── syscalls.inc       Linux x86-64 syscall numbers + socket / TCP constants
└── macros.inc         Project-wide constants (N_DIMS=14, N_CLUSTERS=2048, K_NEIGHBORS=5, NPROBE_INITIAL=12, …)

scripts/
├── build-image.sh     Builds the Docker image (multi-stage: asm-builder → idx-builder → runtime)
└── profile.sh         Brings the stack up via docker compose, runs k6, dumps the result

Dockerfile             Multi-stage build, slim debian runtime
docker-compose.yml     1 LB + 2 APIs, default bridge, cgroup 1 CPU + 350 MB total
```

## Build & run

```bash
make -C asm                  # builds asm_server, asm_lb, asm_build_index (+ unit tests)
./scripts/build-image.sh     # rebuild docker image
./scripts/profile.sh 1       # one cold k6 run, prints p99 + final score
```

## Low-level optimizations applied

- **io_uring throughout** — multishot accept (LB), multishot recv with `IORING_REGISTER_PBUF_RING` provided buffers (API), registered ctrl-fd, `IORING_SETUP_SINGLE_ISSUER | DEFER_TASKRUN | SUBMIT_ALL`, NAPI busy-poll (`IORING_REGISTER_NAPI`).
- **SCM_RIGHTS fd handoff** — LB accepts on TCP, sends `client_fd` over Unix socket to API; API takes ownership.  Hardlinked `sendmsg → close` SQEs.  Pre-initialised `msghdr` pool (512 entries) cycled round-robin.
- **`TCP_NODELAY` + `TCP_QUICKACK` + `TCP_DEFER_ACCEPT`** — LB sets `NODELAY` + `DEFER_ACCEPT` on the listen socket (inherited).  API re-sets `TCP_QUICKACK` on each accepted client fd received via SCM_RIGHTS, so the first response skips the delayed-ACK window.
- **Pre-rendered HTTP responses** in `.rodata` (6 fraud-score buckets + `ready` + `400`) — `handle_request` resolves to a `(pointer, length)` lookup once `fraud_count` is known.
- **Dual-chain AVX2 accumulators** in both `scan_cluster` and `compute_cluster_packed` — halves the serial `vpaddd` dependency chain across the 7 pair groups.
- **FMA3** in `vectorize.asm` CLAMP01_I16 (preloaded `c_scale` / `c_half` in `xmm14`/`xmm15`) and in `parse_number`'s fractional accumulation (`vfmadd213sd`).
- **AVX2 SIMD HTTP framing** — `CRLFCRLF` detection in `http_frame` via shifted broadcast-compare against `\r` and `\n`, ANDed bitmasks, `tzcnt` for first match.  `key_eq` uses 8-byte qword XOR + `bzhi` tail mask.
- **MCC lookup** as a 1-cache-line AVX2 broadcast-compare against 9 overrides + default (was a 20 KB table).
- **`mmap` + `mlock` + `MADV_HUGEPAGE` + `MADV_WILLNEED` + `MAP_POPULATE`** on every index partition file — keeps the index resident and demand-pages everything at startup.
- **Multi-phase startup warm-up** — synthetic searches that train the BPU and load cluster pair-arrays into L3; a `fork()`'d self-warm child that opens TCP connections back to the LB so the bridge NAT path, docker-proxy and the LB→API SCM_RIGHTS chain are all primed before the first real request.
- **Defensive parsing** — strict ISO 8601 separator validation + optional `Z` / `±HH:MM` suffix, bounds-checked cmsg walker, `MSG_CMSG_CLOEXEC` on every recvmsg, `Content-Length` cap, NaN guard in vectorize, saturating cap on `parse_int32` to defend against truncation attacks.

## Resource budget (Rinha 2026 limits)

| Service | CPU | Memory |
|---|---|---|
| `lb`   | 0.05 | 8 MB |
| `api1` | 0.475 | 171 MB |
| `api2` | 0.475 | 171 MB |
| **total** | **1.00** | **350 MB** |
