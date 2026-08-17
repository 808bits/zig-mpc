# zig-mpc - thin wrapper over `zig build`.
#
# The build graph lives in build.zig; this file only gives the steps short,
# discoverable names and a place to hang the parts that are not zig steps
# (`zig fmt`, cleaning the cache).
#
#   make            build the CLI, the static library and the C header
#   make help       list every target
#
# Variables:
#   ZIG=zig                     compiler to use
#   OPTIMIZE=Debug              Debug | ReleaseSafe | ReleaseFast | ReleaseSmall
#   TARGET=                     cross-compilation target triple, e.g. aarch64-linux
#   PREFIX=zig-out              install destination
#   ARGS=                       arguments forwarded by `make run` and `make e2e`

ZIG      ?= zig
OPTIMIZE ?= Debug
PREFIX   ?= zig-out
TARGET   ?=
ARGS     ?=

ZIGFLAGS := -Doptimize=$(OPTIMIZE) --prefix $(PREFIX)
ifneq ($(TARGET),)
ZIGFLAGS += -Dtarget=$(TARGET)
endif

.PHONY: all build release install test e2e e2e-fast check \
        wasm wasm-test run cli fmt fmt-check clean distclean help

## build the CLI, static library and C header into $(PREFIX)
all build:
	$(ZIG) build $(ZIGFLAGS)

## build everything optimized for speed
release:
	$(MAKE) build OPTIMIZE=ReleaseFast

## alias for `make build`; set PREFIX to install elsewhere
install: build

## unit tests, CLI tests and the C ABI smoke test
test:
	$(ZIG) build $(ZIGFLAGS) test

## multi-process end-to-end test; every party in its own process
## pass ARGS=fast to skip the slow CGGMP24 ECDSA flow
e2e:
	$(ZIG) build $(ZIGFLAGS) e2e -- $(ARGS)

## e2e without the CGGMP24 ECDSA flow
e2e-fast:
	$(MAKE) e2e ARGS=fast

## everything that can fail in CI: formatting, tests, e2e and the wasm module
check: fmt-check test e2e wasm-test

## the WebAssembly module (zig-out/bin/zmpc.wasm)
wasm:
	$(ZIG) build $(ZIGFLAGS) wasm

## run the wasm module under node
wasm-test:
	$(ZIG) build $(ZIGFLAGS) wasm-test

## run the CLI: make run ARGS="simulate all"; without ARGS, show help
run cli: build
	$(PREFIX)/bin/zmpc $(or $(ARGS),help)

## rewrite sources in canonical style
fmt:
	$(ZIG) fmt build.zig build.zig.zon src cli

## fail if any source is not in canonical style
fmt-check:
	$(ZIG) fmt --check build.zig build.zig.zon src cli

## remove build outputs, keep the compilation cache
clean:
	rm -rf zig-out zmpc-spool

## remove build outputs and the compilation cache
distclean: clean
	rm -rf .zig-cache

## list every target
help:
	@echo 'zig-mpc - targets:'
	@echo
	@awk '/^## / { doc = doc substr($$0, 4) "\n"; next } \
	      /^[a-z][a-z0-9 -]*:/ && doc { \
	          split($$0, part, ":"); \
	          n = split(doc, lines, "\n"); \
	          printf "  \033[1m%-12s\033[0m %s\n", part[1], lines[1]; \
	          for (i = 2; i < n; i++) printf "  %-12s %s\n", "", lines[i]; \
	          doc = ""; next } \
	      { doc = "" }' $(MAKEFILE_LIST)
	@echo
	@echo 'Variables: ZIG OPTIMIZE TARGET PREFIX ARGS (see the top of the Makefile)'
