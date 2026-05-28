# Pure-asm rinha-de-backend-2026 — build rules.
#
# Each *.asm builds to a static, no-libc ELF64 binary. Includes (*.inc) are
# dependency-tracked manually for now (small project).
#
# Targets:
#   make         — build all binaries
#   make hello   — build the toolchain validator
#   make clean   — remove build artifacts
#   make test    — run hello as a smoke test

NASM      ?= nasm
LD        ?= ld

NASMFLAGS  = -felf64 -g -F dwarf -Wall -Wno-unknown-warning
LDFLAGS    = -static -nostdlib --gc-sections

BUILDDIR   = build

# All asm modules currently buildable.
BINS = hello test_mcc test_vectorize

# Library-style modules (no _start, linked into other binaries).
LIB_OBJS = $(BUILDDIR)/mcc.o $(BUILDDIR)/vectorize.o $(BUILDDIR)/search.o $(BUILDDIR)/parse.o $(BUILDDIR)/server.o $(BUILDDIR)/lb.o $(BUILDDIR)/build_index.o

# Production server binary: server.o owns _start and pulls in every module.
SERVER_BIN      = $(BUILDDIR)/asm_server
LB_BIN          = $(BUILDDIR)/asm_lb
BUILD_INDEX_BIN = $(BUILDDIR)/asm_build_index

# Shared includes — touching any of these rebuilds everything.
INCS = syscalls.inc macros.inc

.PHONY: all clean test
all: $(addprefix $(BUILDDIR)/,$(BINS)) $(LIB_OBJS) $(SERVER_BIN) $(LB_BIN) $(BUILD_INDEX_BIN)

$(BUILDDIR):
	mkdir -p $@

$(BUILDDIR)/%.o: %.asm $(INCS) | $(BUILDDIR)
	$(NASM) $(NASMFLAGS) $< -o $@

$(BUILDDIR)/hello: $(BUILDDIR)/hello.o
	$(LD) $(LDFLAGS) -o $@ $<

$(BUILDDIR)/test_mcc: $(BUILDDIR)/test_mcc.o $(BUILDDIR)/mcc.o
	$(LD) $(LDFLAGS) -o $@ $^

$(BUILDDIR)/test_vectorize: $(BUILDDIR)/test_vectorize.o $(BUILDDIR)/vectorize.o $(BUILDDIR)/mcc.o
	$(LD) $(LDFLAGS) -o $@ $^

$(SERVER_BIN): $(BUILDDIR)/server.o $(BUILDDIR)/parse.o $(BUILDDIR)/vectorize.o $(BUILDDIR)/search.o $(BUILDDIR)/mcc.o
	$(LD) $(LDFLAGS) -o $@ $^

$(LB_BIN): $(BUILDDIR)/lb.o
	$(LD) $(LDFLAGS) -o $@ $^

$(BUILD_INDEX_BIN): $(BUILDDIR)/build_index.o $(BUILDDIR)/parse.o
	$(LD) $(LDFLAGS) -o $@ $^

test: $(BUILDDIR)/hello $(BUILDDIR)/test_mcc $(BUILDDIR)/test_vectorize
	@$(BUILDDIR)/hello && echo "[OK] toolchain"
	@$(BUILDDIR)/test_mcc
	@$(BUILDDIR)/test_vectorize

clean:
	rm -rf $(BUILDDIR)
