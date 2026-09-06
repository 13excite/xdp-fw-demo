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

// stat slots in the xdpfw_stats per-CPU array (keep in sync with main.go)
#define STAT_PKTS_TOTAL 0
#define STAT_IPV4_MATCH 1
#define STAT_IPV6_MATCH 2
#define STAT_PASSED 3
#define STAT_SLOTS 8

// LPM-trie keys: a u32 prefix length followed by the address bytes in
// network byte order (most significant byte first), which is exactly how
// addresses sit in the packet.
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
