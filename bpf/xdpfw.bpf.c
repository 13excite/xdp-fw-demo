//
// xdp-fw-demo: a stateless XDP IPv4/IPv6 firewall.
//
// For every received packet the program looks up the SOURCE IP address in
// an LPM-trie blocklist (one map for IPv4, one for IPv6). On a match the
// packet is dropped (XDP_DROP); otherwise it is passed to the normal
// network stack (XDP_PASS). Non-IP traffic is always passed.
//
// The blocklist maps are filled from user space by cmd/xdpfw. The allowed
// prefix range is enforced there: /16../32 for IPv4 and /64../128 for
// IPv6 (a bare address is /32 or /128).
//
// The header-parsing style, pinned BTF-defined maps and per-CPU counter
// pattern follow bpf/yadns-xdp.bpf.c from the yadns-controller project,
// reworked here as a plain firewall with no packet rewriting.
//

#include "xdpfw.bpf.h"

// IPv4 blocklist, longest-prefix match on the packet source address.
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_v4_key);
    __type(value, __u8);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} blocklist_v4 SEC(".maps");

// IPv6 blocklist, longest-prefix match on the packet source address.
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_v6_key);
    __type(value, __u8);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} blocklist_v6 SEC(".maps");

// per-CPU counters, read back by "xdpfw stats"
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, STAT_SLOTS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdpfw_stats SEC(".maps");

// Set from user space at load time ("xdpfw attach -dry-run"): when non-zero,
// matches are still counted but the packet is passed instead of dropped.
volatile const __u8 xdpfw_dry_run = 0;

static __always_inline void stat_inc(__u32 slot) {
    __u64* v = bpf_map_lookup_elem(&xdpfw_stats, &slot);
    if (v)
        *v += 1;
}

SEC("xdp")
int xdp_fw(struct xdp_md* ctx) {
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;

    stat_inc(STAT_PKTS_TOTAL);

    struct ethhdr* eth = data;
    if ((void*)(eth + 1) > data_end)
        return XDP_PASS;

    __be16 proto = eth->h_proto;
    void* nh = (void*)(eth + 1);

    // accept a single VLAN tag
    if (proto == bpf_htons(ETH_P_8021Q) || proto == bpf_htons(ETH_P_8021AD)) {
        struct vlan_hdr* vh = nh;
        if ((void*)(vh + 1) > data_end)
            return XDP_PASS;
        proto = vh->encap_proto;
        nh = (void*)(vh + 1);
    }

    if (proto == bpf_htons(ETH_P_IP)) {
        struct iphdr* ip = nh;
        if ((void*)(ip + 1) > data_end)
            return XDP_PASS;

        struct lpm_v4_key key = {};
        key.prefixlen = 32;
        __builtin_memcpy(key.addr, &ip->saddr, sizeof(key.addr));

        if (bpf_map_lookup_elem(&blocklist_v4, &key)) {
            stat_inc(STAT_IPV4_MATCH);
            if (!xdpfw_dry_run)
                return XDP_DROP;
        }
    } else if (proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr* ip6 = nh;
        if ((void*)(ip6 + 1) > data_end)
            return XDP_PASS;

        struct lpm_v6_key key = {};
        key.prefixlen = 128;
        __builtin_memcpy(key.addr, &ip6->saddr, sizeof(key.addr));

        if (bpf_map_lookup_elem(&blocklist_v6, &key)) {
            stat_inc(STAT_IPV6_MATCH);
            if (!xdpfw_dry_run)
                return XDP_DROP;
        }
    }

    stat_inc(STAT_PASSED);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
