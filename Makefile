BIN := bin/xdpfw

.PHONY: all bpf cli clean

all: bpf cli

# build the XDP object (needs clang/llvm + bpftool on a Linux host)
bpf:
	$(MAKE) -C bpf

# build the user-space loader/CLI
cli:
	CGO_ENABLED=0 go build -o $(BIN) ./cmd/xdpfw
	@echo "built $(BIN)"

clean:
	$(MAKE) -C bpf clean
	rm -rf bin
