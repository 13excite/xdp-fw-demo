//
// xdp-fw-demo: a stateless XDP IPv4/IPv6 firewall.
//
// For every received packet the program looks up the SOURCE IP address
// first in an LPM-trie allowlist (one map per family) and, on a match,
// passes the packet immediately. Otherwise it looks the address up in
// an LPM-trie blocklist; on a match the packet is dropped (XDP_DROP)
// unless dryrun is set, in which case it is only counted. Everything
// else is passed to the normal network stack (XDP_PASS). Non-IP
// traffic is always passed.
//
// Maps:
//   blocklist_v4 / blocklist_v6   LPM_TRIE  source prefixes to drop
//   allowlist_v4 / allowlist_v6   LPM_TRIE  source prefixes to always pass
//   xdpfw_stats                   PERCPU_ARRAY  counters for "firewall stats"
//   xdpfw_metrics                 ARRAY u64     rx/pass/drop/... counters
//   xdpfw_perf                    ARRAY u64     packet-size histogram
//   xdpfw_runtime_config          ARRAY u32     runtime dryrun toggle
//
// The header-parsing style, pinned BTF-defined maps and per-CPU counter
// pattern follow bpf/yadns-xdp.bpf.c from the yadns-controller project,
// reworked here as a plain firewall with no packet rewriting.
//

#include "xdpfw.bpf.h"

// IPv4 / IPv6 blocklist, longest-prefix match on the packet source address.
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_v4_key);
    __type(value, __u8);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    XDPFW_PIN;
} blocklist_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_v6_key);
    __type(value, __u8);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    XDPFW_PIN;
} blocklist_v6 SEC(".maps");

// IPv4 / IPv6 allowlist ("pass" maps): a match here short-circuits to
// XDP_PASS before the blocklist is consulted.
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_v4_key);
    __type(value, __u8);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    XDPFW_PIN;
} allowlist_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_v6_key);
    __type(value, __u8);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    XDPFW_PIN;
} allowlist_v6 SEC(".maps");

// per-CPU counters, read back by "xdpfw firewall stats"
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, STAT_SLOTS);
    XDPFW_PIN;
} xdpfw_stats SEC(".maps");

// plain u64 counter array, read back by "xdpfw firewall metrics"
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, XDPFW_M_SLOTS);
    XDPFW_PIN;
} xdpfw_metrics SEC(".maps");

// packet-size histogram: bucket = min(63, ilog2(len))
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, XDPFW_PERF_SLOTS);
    XDPFW_PIN;
} xdpfw_perf SEC(".maps");

// runtime configuration set from user space; index 0 is the dryrun flag
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, XDPFW_CFG_SLOTS);
    XDPFW_PIN;
} xdpfw_runtime_config SEC(".maps");

// Set from user space at load time via the variables api:
//   xdpfw_dry_run          initial dryrun value (also toggled at runtime)
//   xdpfw_metrics_enabled  populate xdpfw_metrics when non-zero
//   xdpfw_perf_enabled     populate xdpfw_perf when non-zero
volatile const __u8 xdpfw_dry_run = 0;
volatile const __u8 xdpfw_metrics_enabled = 0;
volatile const __u8 xdpfw_perf_enabled = 0;

static __always_inline void stat_inc(__u32 slot) {
    __u64* v = bpf_map_lookup_elem(&xdpfw_stats, &slot);
    if (v)
        *v += 1;
}

static __always_inline void metric_inc(__u32 slot) {
    if (!xdpfw_metrics_enabled)
        return;
    __u64* v = bpf_map_lookup_elem(&xdpfw_metrics, &slot);
    if (v)
        __sync_fetch_and_add(v, 1);
}

static __always_inline void perf_observe(__u32 len) {
    if (!xdpfw_perf_enabled)
        return;

    __u32 bucket = 0;
#pragma unroll
    for (int i = 0; i < XDPFW_PERF_SLOTS - 1; i++) {
        if (len <= 1U)
            break;
        len >>= 1;
        bucket++;
    }

    __u64* v = bpf_map_lookup_elem(&xdpfw_perf, &bucket);
    if (v)
        __sync_fetch_and_add(v, 1);
}

static __always_inline __u8 runtime_dryrun(void) {
    __u32 key = XDPFW_CFG_DRYRUN;
    __u32* v = bpf_map_lookup_elem(&xdpfw_runtime_config, &key);
    if (v && *v)
        return 1;
    return xdpfw_dry_run;
}

SEC("xdp")
int xdp_fw(struct xdp_md* ctx) {
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;

    stat_inc(STAT_PKTS_TOTAL);
    metric_inc(XDPFW_M_RX);
    perf_observe((__u32)(data_end - data));

    struct ethhdr* eth = data;
    if ((void*)(eth + 1) > data_end)
        goto pass;

    __be16 proto = eth->h_proto;
    void* nh = (void*)(eth + 1);

    // accept a single VLAN tag
    if (proto == bpf_htons(ETH_P_8021Q) || proto == bpf_htons(ETH_P_8021AD)) {
        struct vlan_hdr* vh = nh;
        if ((void*)(vh + 1) > data_end)
            goto pass;
        proto = vh->encap_proto;
        nh = (void*)(vh + 1);
    }

    if (proto == bpf_htons(ETH_P_IP)) {
        struct iphdr* ip = nh;
        if ((void*)(ip + 1) > data_end)
            goto pass;

        struct lpm_v4_key key = {};
        key.prefixlen = 32;
        __builtin_memcpy(key.addr, &ip->saddr, sizeof(key.addr));

        if (bpf_map_lookup_elem(&allowlist_v4, &key)) {
            metric_inc(XDPFW_M_ALLOW_HIT);
            goto pass;
        }

        if (bpf_map_lookup_elem(&blocklist_v4, &key)) {
            stat_inc(STAT_IPV4_MATCH);
            metric_inc(XDPFW_M_BLOCK_V4);
            if (!runtime_dryrun()) {
                metric_inc(XDPFW_M_DROP);
                return XDP_DROP;
            }
        }
    } else if (proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr* ip6 = nh;
        if ((void*)(ip6 + 1) > data_end)
            goto pass;

        struct lpm_v6_key key = {};
        key.prefixlen = 128;
        __builtin_memcpy(key.addr, &ip6->saddr, sizeof(key.addr));

        if (bpf_map_lookup_elem(&allowlist_v6, &key)) {
            metric_inc(XDPFW_M_ALLOW_HIT);
            goto pass;
        }

        if (bpf_map_lookup_elem(&blocklist_v6, &key)) {
            stat_inc(STAT_IPV6_MATCH);
            metric_inc(XDPFW_M_BLOCK_V6);
            if (!runtime_dryrun()) {
                metric_inc(XDPFW_M_DROP);
                return XDP_DROP;
            }
        }
    }

pass:
    stat_inc(STAT_PASSED);
    metric_inc(XDPFW_M_PASS);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
