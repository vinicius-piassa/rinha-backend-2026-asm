# syntax=docker/dockerfile:1.6
#
# Two-stage build for the pure-asm Rinha 2026 entry.
#
#   stage 1 (asm-builder): nasm + GNU ld → asm_lb, asm_server, asm_build_index
#   stage 2 (runtime):     `scratch` image carrying only the static binaries
#                          + the pre-built index.bin.  No libc, no shell.
#
# index.bin (the IVF k-NN index over the official references corpus) is
# generated offline by `asm_build_index` and committed to the repo; this
# keeps `docker compose up -d` under the Rinha CI's 5-minute timeout because
# k-means clustering (the slow part, ~10 min single-threaded) never runs at
# image-build time.  Regenerate locally with
#     make -C asm && asm/build/asm_build_index references.json index.bin
# whenever the corpus or the index format changes.

# ============================================================================
# Stage 1 — assemble the static no-libc binaries
# ============================================================================
FROM debian:bookworm-slim AS asm-builder

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        nasm binutils make && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY asm/ ./asm/
RUN make -C asm clean && make -C asm all

# ============================================================================
# Stage 2 — minimal runtime image
# ============================================================================
FROM scratch

COPY --from=asm-builder /src/asm/build/asm_lb     /asm_lb
COPY --from=asm-builder /src/asm/build/asm_server /asm_server
COPY index.bin                                    /index.bin

# Default to LB so `docker run rinha-asm` does something sensible.
ENTRYPOINT []
CMD ["/asm_lb", "9999", "/sockets/api1.sock", "/sockets/api2.sock"]
