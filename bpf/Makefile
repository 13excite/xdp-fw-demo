# Build the XDP firewall object (xdpfw.bpf.o).
#
# Requirements on the build host (Linux):
#   * clang / llvm  (>= 11)
#   * bpftool       (to generate vmlinux.h from kernel BTF)
#   * a kernel with BTF at /sys/kernel/btf/vmlinux (CONFIG_DEBUG_INFO_BTF=y,
#     standard on Ubuntu 20.04+ / kernel >= 5.15)
# libbpf helper headers come from the vendored submodule in ../libbpf.

CLANG      ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL    ?= bpftool

LIBBPF_SRC := ../libbpf/src

ARCH := $(shell uname -m | sed -e 's/x86_64/x86/' -e 's/aarch64/arm64/' -e 's/armv7l/arm/')

TARGET  := xdpfw.bpf.o
SRC     := xdpfw.bpf.c
HEADERS := xdpfw.bpf.h vmlinux.h

CFLAGS := -g -O2 -Wall -Wno-unused-function -fno-stack-protector \
          -target bpf -D__TARGET_ARCH_$(ARCH) -isystem $(LIBBPF_SRC)

.PHONY: all clean
all: $(TARGET)

vmlinux.h:
	@command -v $(BPFTOOL) >/dev/null 2>&1 || { \
		echo "bpftool not found - install it (apt install linux-tools-common linux-tools-$$(uname -r) || apt install bpftool)"; \
		exit 1; }
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(TARGET): $(SRC) $(HEADERS)
	$(CLANG) $(CFLAGS) -c $(SRC) -o $@
	$(LLVM_STRIP) -g $@
	@echo "built $@"

clean:
	rm -f $(TARGET) vmlinux.h
