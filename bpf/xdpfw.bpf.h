#pragma once

// CO-RE: kernel types come from a generated vmlinux.h (see bpf/Makefile).
// libbpf helper headers are taken from the vendored submodule in ../libbpf.
#include "vmlinux.h"
#include <bpf_helpers.h>
#include <bpf_endian.h>

// EtherType constants are plain #defines in <linux/if_ether.h>, which we do
// not include here, so define the few we need.
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif
#ifndef ETH_P_8021Q
#define ETH_P_8021Q 0x8100
#endif
#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8
#endif

// Present as a BTF enum on kernels >= ~5.4, but guard just in case.
#ifndef BPF_F_NO_PREALLOC
#define BPF_F_NO_PREALLOC (1U << 0)
#endif

// Maps are either anonymous or pinned by name. The user-space loader
// expects pinned maps, so the project Makefile builds with
// -D_PINNED_MAP; a bare "make -C bpf" builds anonymous maps.
#ifdef _PINNED_MAP
#define XDPFW_PIN __uint(pinning, LIBBPF_PIN_BY_NAME)
#else
#define XDPFW_PIN
#endif

// xdpfw_stats: per-CPU counters, read back by "xdpfw firewall stats".
// (keep in sync with pkg/plugins/firewall/maps.go)
#define STAT_PKTS_TOTAL 0
#define STAT_IPV4_MATCH 1
#define STAT_IPV6_MATCH 2
#define STAT_PASSED 3
#define STAT_SLOTS 8

// xdpfw_metrics: plain u64 array of counters.
// (keep in sync with pkg/plugins/firewall/maps.go)
#define XDPFW_M_RX 0
#define XDPFW_M_PASS 1
#define XDPFW_M_DROP 2
#define XDPFW_M_ERROR 3
#define XDPFW_M_ALLOW_HIT 4
#define XDPFW_M_BLOCK_V4 5
#define XDPFW_M_BLOCK_V6 6
#define XDPFW_M_SLOTS 64

// xdpfw_perf: packet-size histogram, one bucket per power-of-two.
#define XDPFW_PERF_SLOTS 64

// xdpfw_runtime_config: u32 array set from user space at run time.
#define XDPFW_CFG_DRYRUN 0
#define XDPFW_CFG_SLOTS 16

// LPM-trie keys: a u32 prefix length followed by the address bytes in
// network byte order (most significant byte first), which is exactly how
// addresses sit in the packet. Used by both the blocklist and the
// allowlist maps.
struct lpm_v4_key {
    __u32 prefixlen;
    __u8 addr[4];
};

struct lpm_v6_key {
    __u32 prefixlen;
    __u8 addr[16];
};

// single 802.1Q / 802.1ad VLAN tag
struct vlan_hdr {
    __be16 tci;
    __be16 encap_proto;
};
