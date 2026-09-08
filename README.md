# xdp-fw-demo

A **stateless XDP IPv4/IPv6 source-address firewall**, packaged as a long-lived
service. 

An XDP program matches every incoming packet's **source IP** against two
LPM-trie maps:

* **allowlist** — a match passes the packet immediately (`XDP_PASS`);
* **blocklist** — a match drops the packet (`XDP_DROP`), or only counts it when
  dryrun is enabled.

The user space side is a cobra CLI: `xdpfw server start` runs the daemon
(attach + pin + HTTP API + plugins), and the other subcommands are thin clients
that call the running daemon's API on `/api/v1.0`.

## Architecture

```
cmd/xdpfw/                thin main + cobra commands (root, server, version)
pkg/controller/           wires config + logger + api + plugins, runs them under one errgroup
pkg/internal/log/         zap + lumberjack logger
pkg/internal/config/      YAML config (TGlobal / TConfig / TRuntime)
pkg/internal/api/         echo HTTP server (/api/v1.0) + client
pkg/plugins/              IPlugin interface + registry
pkg/plugins/metrics/      metrics plugin: store / aggregate / export counters
pkg/plugins/firewall/     the "offloader" analogue: XDP load, map plumbing, REST, CLI
bpf/xdpfw.bpf.c|.h        XDP program + maps
```

The daemon runs under `errgroup` with SIGINT/SIGTERM handling: on a signal the
XDP link is unpinned, the program detached, and every plugin's context
cancelled.

### Loader modes

`firewall.loader.mode` is `primary` (attach the program to the interface and pin
the `bpf_link`), `secondary` (register the program FD into an already-attached
program's tail-call hook map), or `auto` (detect from the interface state and the
configured hook pin path).

## Maps

| map                    | type           | key                            | purpose                                   |
|------------------------|----------------|--------------------------------|-------------------------------------------|
| `blocklist_v4/v6`      | `LPM_TRIE`     | `{u32 prefixlen; u8 addr[N]}`  | source prefixes to drop                    |
| `allowlist_v4/v6`      | `LPM_TRIE`     | `{u32 prefixlen; u8 addr[N]}`  | source prefixes to always pass             |
| `xdpfw_stats`          | `PERCPU_ARRAY` | `u32` slot                     | `packets_total / *_matched / passed`       |
| `xdpfw_metrics`        | `ARRAY` u64    | `u32` index                    | `rx / pass / drop / error / *_hit` counters|
| `xdpfw_perf`           | `ARRAY` u64    | `u32` bucket                   | packet-size histogram (power-of-two)       |
| `xdpfw_runtime_config` | `ARRAY` u32    | `u32` index                    | index 0 = runtime dryrun toggle            |

All maps are pinned under `/sys/fs/bpf/xdpfw/` (built with `-D_PINNED_MAP`), so
the API handlers and CLI reach them without reloading the program, and the
program survives the process exiting (the XDP `bpf_link` is pinned as
`link_<iface>`).

Load-time constants set through cilium/ebpf's variables API:
`xdpfw_dry_run`, `xdpfw_metrics_enabled`, `xdpfw_perf_enabled`.

## Prefix policy

Enforced by the API/CLI on insert:

* **IPv4**: `/16` (broadest) .. `/32` (single host)
* **IPv6**: `/64` (broadest) .. `/128` (single host)

A bare address is `/32` or `/128`. Prefixes are masked; anything outside the
range is rejected.

## Build

Needs a **Linux** host (BPF cannot be built/run on macOS): `clang`/`llvm` >= 11,
`bpftool`, a kernel with BTF (`/sys/kernel/btf/vmlinux`, kernel >= 5.15 /
Ubuntu 20.04+), Go >= 1.22.

```sh
git clone --recurse-submodules <this repo>
cd xdp-fw-demo
go mod tidy
make                 # builds bpf/xdpfw.bpf.o (pinned maps) and bin/xdpfw
```

`make` targets: `build` (bpf + cli), `bpf`, `cli`, `fmt` (gofmt), `test`,
`run` (`sudo bin/xdpfw -C xdpfw.yaml server start --debug`), `clean`.
Version / build date / git revision are stamped into the binary via `-ldflags`
(see `VERSION.txt`).

## Use (run as root)

```sh
# start the daemon (attaches XDP to the configured interface, serves the api)
sudo ./bin/xdpfw -C xdpfw.yaml server start --debug

# --- in another shell, talking to the running daemon ---

# blocklist / allowlist
sudo ./bin/xdpfw -C xdpfw.yaml firewall add   203.0.113.7 198.51.100.0/24 2001:db8:1234::/64
sudo ./bin/xdpfw -C xdpfw.yaml firewall allow 203.0.113.7
sudo ./bin/xdpfw -C xdpfw.yaml firewall del   198.51.100.0/24
sudo ./bin/xdpfw -C xdpfw.yaml firewall list           # add --allow for the allowlist
sudo ./bin/xdpfw -C xdpfw.yaml firewall flush           # add --allow for the allowlist

# counters
sudo ./bin/xdpfw -C xdpfw.yaml firewall stats
sudo ./bin/xdpfw -C xdpfw.yaml firewall metrics
sudo ./bin/xdpfw -C xdpfw.yaml metrics show

# runtime dryrun (count matches, never drop)
sudo ./bin/xdpfw -C xdpfw.yaml firewall control bpf dryrun --on
sudo ./bin/xdpfw -C xdpfw.yaml firewall control bpf dryrun --off
```

## HTTP API (`/api/v1.0`)

| method + path                        | purpose                                   |
|--------------------------------------|-------------------------------------------|
| `GET  /ping`                         | liveness                                  |
| `GET  /firewall/ping`                | firewall plugin liveness                  |
| `GET  /firewall/blocklist`           | list blocklist entries (`{v4:[],v6:[]}`)  |
| `POST /firewall/blocklist`           | add — body `{"entries":["ip|cidr", ...]}` |
| `DELETE /firewall/blocklist`         | remove — same body                        |
| `POST /firewall/blocklist/flush`     | empty the blocklist                       |
| `.../allowlist` (+ `/flush`)         | same shape for the allowlist              |
| `GET  /firewall/stats`               | `xdpfw_stats` sums                        |
| `GET  /firewall/metrics`             | `xdpfw_metrics` counters + `xdpfw_perf`   |
| `POST /firewall/control/bpf`         | `{"option":"dryrun","value":true}`        |
| `GET  /metrics` , `/metrics/:id`     | aggregated metrics as JSON                |

Every mutating request accepts `"dryrun": true` to validate and report without
touching the maps.

## Quick loopback test (`-mode generic`, config `interface: "lo"`)

```sh
sudo ./bin/xdpfw -C xdpfw.yaml server start --debug &
sudo ./bin/xdpfw -C xdpfw.yaml firewall add 127.0.0.2/32   # /16../32 allowed
ping -c2 127.0.0.1                                          # still works
sudo ./bin/xdpfw -C xdpfw.yaml firewall stats
```

> `127.0.0.0/8` is broader than `/16` and is rejected by the prefix policy;
> block a concrete host such as `127.0.0.2/32` for a loopback test.

## Notes / extending

* **Direction**: matches `saddr`. Switch `&ip->saddr` / `&ip6->saddr` to the
  `daddr` fields in `bpf/xdpfw.bpf.c` for an egress-style filter.
* **Dryrun**: `firewall.options.dryrun` sets it at load time; `firewall control
  bpf dryrun --on/--off` toggles `xdpfw_runtime_config[0]` at runtime. Effective
  dryrun is `xdpfw_dry_run || runtime_config[0]`.
* **Capacity**: each LPM map holds 65536 entries; bump `max_entries` in
  `xdpfw.bpf.c`.
* **`vmlinux.h`** is generated by `bpf/Makefile` from the running kernel's BTF
  and is git-ignored.
* **Not in this build**: `monitor` / `receiver` plugins, native/offload attach
  modes (the loader uses generic/SKB mode).
