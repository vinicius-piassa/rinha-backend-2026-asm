# rinha-asm

Submission for [Rinha de Backend 2026](https://github.com/zanfranceschi/rinha-de-backend-2026) written in **pure x86-64 NASM assembly** — no libc, no runtime, no framework, no managed allocator.  Statically linked against bare Linux syscalls.

## Architecture

```
client → :9999 (TCP) → asm_lb ──SCM_RIGHTS──▶ asm_server (×2) ──TCP──▶ client
                          │                        │
                          ▼                        ▼
                    accept_loop                handle_request
                    send_fd via UDS            parse + vectorize + search + send
```

- **`asm_lb`** — TCP listener.  Accepts new connections and hands the client fd to one of the API workers over a Unix-domain socket using `sendmsg(SCM_RIGHTS)`.  Round-robin balancing.  Zero byte-proxying after the handoff.
- **`asm_server`** — API worker.  Receives client fds from the LB via `recvmsg`, registers them with `epoll`, then runs the full HTTP pipeline (`recvfrom` → frame → parse JSON → vectorize → IVF k-NN search → emit pre-rendered HTTP response → `sendto`).
- **`asm_build_index`** — offline tool.  Parses the `references.json.gz` corpus, runs k-means clustering (2048 clusters, 14 dims, 20 iters), builds an IVF index with per-cluster bbox lower bounds, writes the binary index that the servers mmap at startup.

## Fraud-detection model

IVF k-NN with `K = 5` neighbours, branchless top-K kept in a packed `(distance << 22) | reference_idx` key, 14-dimensional `int16` quantized vectors, AVX2 SIMD throughout (`vpmaddwd` for squared L2, `vpcmpgtq` for cluster min selection, `vpackssdw` + `vpermq` for f32→i16 conversion).  Per-cluster axis-aligned bounding boxes give a cheap lower bound that lets `search_core` skip the long tail of clusters without scanning their vectors.

## Repo layout

```
asm/
├── server.asm         API worker: HTTP framing + epoll event loop + warm-up
├── lb.asm             Load balancer: TCP accept + SCM_RIGHTS handoff
├── build_index.asm    Offline index builder: parse_refs + kmeans + bbox_pack + write_index_bin
├── parse.asm          JSON parser (skip_ws + parse_number + parse_iso8601 + sub-object dispatchers)
├── vectorize.asm      Request → 14-dim i16 Query  (clamp01 + i16 quantization)
├── search.asm         IVF k-NN  (compute_cluster_packed + pick_min_cluster + scan_cluster + search_core)
├── mcc.asm            MCC risk lookup (10000-entry i16 table)
├── uring.asm/uring.inc  io_uring helpers — compiled but currently gc-sectioned at link
├── syscalls.inc       Linux x86-64 syscall numbers + socket / epoll / TCP constants
└── macros.inc         Project-wide constants  (N_DIMS=14, N_CLUSTERS=2048, K_NEIGHBORS=5, …)

scripts/
├── build-image.sh     Builds the Docker image  (3-stage: asm-builder → idx-builder → scratch runtime)
└── profile.sh         Brings the stack up via docker compose, runs k6, dumps the result

Dockerfile             3-stage build, scratch runtime  (final image ≈ 87 MB, dominated by index.bin)
docker-compose.yml     1 LB + 2 APIs, bridge network, cgroup 1 CPU + 350 MB total
```

## Build & run

```bash
make -C asm                  # builds asm_server, asm_lb, asm_build_index (+ unit tests)
./scripts/build-image.sh     # rebuild docker image  (~10 min — k-means dominates)
./scripts/profile.sh 1       # one cold k6 run, prints p99 + final score
```

For a quick smoke test without docker, point the binaries at host-local Unix sockets:

```bash
asm/build/asm_server /tmp/api1.sock /tmp/index.bin &
asm/build/asm_server /tmp/api2.sock /tmp/index.bin &
sleep 4                                              # warm-up
asm/build/asm_lb 9999 /tmp/api1.sock /tmp/api2.sock &
sleep 1
curl -sS -X POST http://localhost:9999/fraud-score -d @payload.json
```

## Low-level optimizations applied

- **Edge-triggered epoll (`EPOLLET`) + drain loop on client recv** — one event handler drains every byte in the socket, cutting redundant epoll wake-ups under load.  `O_NONBLOCK` + `MSG_DONTWAIT` + explicit `-EAGAIN` handling.
- **`EPOLLRDHUP`** for earlier peer-half-close detection.
- **`TCP_NODELAY` + `TCP_QUICKACK` + `TCP_NOTSENT_LOWAT=128`** per client fd.
- **`TCP_DEFER_ACCEPT` + `SO_REUSEPORT`** on the LB listener — kernel only signals readable once the first byte of the POST arrives.
- **Pre-rendered HTTP responses** in `.rodata` (6 fraud-score buckets + `ready` + `400`) — `handle_request` is a pointer + length lookup once `fraud_count` is known.
- **`mlockall(MCL_CURRENT | MCL_FUTURE)`** + `MAP_POPULATE` + `MADV_HUGEPAGE` on the index mmap — keeps the 87 MB index resident.
- **`PR_SET_TIMERSLACK = 1`** to tighten scheduler wake-up jitter from the default 50 µs to 1 ns.
- **Multi-phase startup warm-up** — 10 000 synthetic searches that train the BPU and load every cluster pair-array into L3, 1 000 iterations of the full `handle_request` pipeline against a static POST baked into `.rodata`, dummy `epoll_create1` / `pipe2` / `read` / `write` syscalls to warm kernel paths.  A second `fork()`'d *self-warm* child opens 32 TCP connections back to the LB so docker-proxy, the bridge NAT path, and the LB→API SCM_RIGHTS chain are all primed before the first real request.
- **`cpuset` pinning** in compose — each API pinned to a dedicated physical core (both SMT threads).
- **`cap_add: IPC_LOCK`** + `ulimits.memlock=-1` so `mlockall` actually pins.

A complete io_uring path (multishot accept + multishot recv + provided buffer ring + registered files, including the buf-ring `BUF_LEN` offset bug we hit and fixed) is compiled into the source but `--gc-sections` drops it at link time.

## Resource budget (Rinha 2026 limits)

| Service | CPU | Memory |
|---|---|---|
| `lb`   | 0.05 | 30 MB |
| `api1` | 0.475 | 160 MB |
| `api2` | 0.475 | 160 MB |
| **total** | **1.00** | **350 MB** |

## Status

Detection: `100% true_positive` + `100% true_negative` (0 FP, 0 FN, 0 HTTP errors) over the full 54 100-request k6 ramp 1 → 900 rps for 120 s.  p99 hovers in the **1.40 ms ± 30 ms** band on this host's `docker compose` (bridge + `userland-proxy: true`), giving a final score around **5840 / 6000**.  On bare metal the same binaries hit **~1.0 ms p99 / 6000**.
