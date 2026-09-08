#
# Makefile to build the xdpfw controller (binary + XDP object).
#

EXECUTABLE := bin/xdpfw
PROJECT    := xdpfw
BPFOBJ     := bpf/xdpfw.bpf.o
CONFIG     := xdpfw.yaml

GO   ?= go
GOFMT ?= gofmt -w
ECHO  = echo

# maps are pinned by name so the api and the cli can reach them
PINNED_FLAGS ?= -D_PINNED_MAP

PROJECT_HOME := $(dir $(realpath $(firstword $(MAKEFILE_LIST))))

BUILD_DATE  := $(shell date +%FT%T%z)
VERSION     := $(shell cat $(PROJECT_HOME)/VERSION.txt)
GITREVISION := $(shell git -C $(PROJECT_HOME) rev-parse --short HEAD 2>/dev/null || echo none)

TAGS ?=

.PHONY: all build bpf cli fmt test run clean

all: build

# full build: XDP object + user-space controller
build: bpf cli

# build the XDP object (needs clang/llvm + bpftool on a Linux host)
bpf:
	@$(ECHO) "Building ebpf $(BPFOBJ) (PINNED_FLAGS='$(PINNED_FLAGS)')"
	$(MAKE) -C bpf clean
	$(MAKE) -C bpf PINNED_FLAGS=$(PINNED_FLAGS)

# gofmt the sources in place
fmt:
	$(GOFMT) ./cmd ./pkg

# build the user-space loader/controller/CLI
cli: fmt
	@$(ECHO) "Build date: '$(BUILD_DATE)' revision: '$(GITREVISION)' version: '$(VERSION)'"
	CGO_ENABLED=0 $(GO) build -v -tags '$(TAGS)' \
	  -ldflags="-X 'main.Version=$(VERSION)' \
	            -X 'main.Date=$(BUILD_DATE)' \
	            -X 'main.Revision=$(GITREVISION)'" \
	  -o $(EXECUTABLE) ./cmd/xdpfw
	@$(EXECUTABLE) version || true
	@$(ECHO) "built $(EXECUTABLE)"

test:
	@$(ECHO) "Running tests for '$(PROJECT)' ..."
	$(GO) test ./...

# run the daemon on the example configuration (needs root)
run: build
	sudo $(EXECUTABLE) -C $(CONFIG) server start --debug

clean:
	@$(ECHO) "Cleaning build"
	$(MAKE) -C bpf clean
	rm -rf bin
