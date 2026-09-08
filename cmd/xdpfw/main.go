// Command xdpfw runs the XDP firewall as a long-lived service and
// provides a client for its http api.
//
//	xdpfw -C xdpfw.yaml server start [--debug]
//	xdpfw firewall add    <ip|cidr> [<ip|cidr> ...]
//	xdpfw firewall del    <ip|cidr> [<ip|cidr> ...]
//	xdpfw firewall allow  <ip|cidr> [<ip|cidr> ...]
//	xdpfw firewall list   [--allow]
//	xdpfw firewall stats
//	xdpfw firewall metrics
//	xdpfw firewall control bpf dryrun --on|--off
//	xdpfw metrics show [name]
//	xdpfw version
//
// The daemon attaches an XDP program that matches every packet's
// SOURCE address against an LPM-trie blocklist (dropped) and
// allowlist (always passed). Allowed prefix lengths: IPv4 /16../32,
// IPv6 /64../128. Runtime ops go through the daemon's /api/v1.0.
package main

import (
	"os"

	"github.com/13excite/xdp-fw-demo/cmd/xdpfw/cmd"
)

const (
	// error on running command
	ExitCodeUnspecified = 1
)

// set via -ldflags at build time (see Makefile)
var (
	Version  = "dev"
	Revision = "none"
	Date     = "unknown"
)

func main() {
	cmd.SetVersion(Version, Revision)
	cmd.SetDate(Date)

	if err := cmd.Execute(); err != nil {
		os.Exit(ExitCodeUnspecified)
	}
}
