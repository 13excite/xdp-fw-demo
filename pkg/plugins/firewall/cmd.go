package firewall

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/spf13/cobra"

	"github.com/13excite/xdp-fw-demo/pkg/internal/api"
)

// cmdFirewall is the "xdpfw firewall ..." command tree. Every
// leaf talks to the running daemon over its http api.
type cmdFirewall struct {
	p *TFirewallPlugin

	// request-level dryrun switch
	dryrun bool
}

func (c *cmdFirewall) Command() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Use = NamePlugin
	cmd.Short = "Manage the running xdp firewall over its api"
	cmd.Long = "Add/remove blocklist and allowlist entries, read counters and " +
		"toggle bpf dryrun on the running daemon"

	cmd.PersistentFlags().BoolVar(&c.dryrun, "dry-run", false,
		"dry-run: validate and report but change nothing")

	cmd.AddCommand(
		c.mutateCmd("add", kindBlock, http.MethodPost, "Block source prefixes"),
		c.mutateCmd("del", kindBlock, http.MethodDelete, "Unblock source prefixes"),
		c.mutateCmd("allow", kindAllow, http.MethodPost, "Add allowlist (pass) prefixes"),
		c.mutateCmd("unallow", kindAllow, http.MethodDelete, "Remove allowlist prefixes"),
		c.listCmd(),
		c.flushCmd(),
		c.statsCmd(),
		c.metricsCmd(),
		c.controlCmd(),
	)
	return cmd
}

func (c *cmdFirewall) client() *api.Client {
	return api.NewClient(c.p.G())
}

func (c *cmdFirewall) do(method, uri string, body []byte) error {
	resp, code, err := c.client().Request(method, uri, body)
	if err != nil {
		return err
	}
	fmt.Println(string(resp))
	if code >= 300 && code != http.StatusMultiStatus {
		return fmt.Errorf("http %d %s", code, http.StatusText(code))
	}
	return nil
}

func (c *cmdFirewall) mutateCmd(use, kind, method, short string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   use + " <ip|cidr> [<ip|cidr> ...]",
		Short: short,
		Args:  cobra.MinimumNArgs(1),
	}
	cmd.RunE = func(_ *cobra.Command, args []string) error {
		req := EntriesReq{Entries: args, Dryrun: c.dryrun}
		body, _ := json.Marshal(req)
		return c.do(method, NamePlugin+"/"+kind, body)
	}
	return cmd
}

func (c *cmdFirewall) listCmd() *cobra.Command {
	var allow bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List blocklist (or --allow allowlist) entries",
	}
	cmd.Flags().BoolVar(&allow, "allow", false, "list the allowlist instead of the blocklist")
	cmd.RunE = func(_ *cobra.Command, _ []string) error {
		kind := kindBlock
		if allow {
			kind = kindAllow
		}
		return c.do(http.MethodGet, NamePlugin+"/"+kind, nil)
	}
	return cmd
}

func (c *cmdFirewall) flushCmd() *cobra.Command {
	var allow bool
	cmd := &cobra.Command{
		Use:   "flush",
		Short: "Empty the blocklist (or --allow allowlist)",
	}
	cmd.Flags().BoolVar(&allow, "allow", false, "flush the allowlist instead of the blocklist")
	cmd.RunE = func(_ *cobra.Command, _ []string) error {
		kind := kindBlock
		if allow {
			kind = kindAllow
		}
		return c.do(http.MethodPost, NamePlugin+"/"+kind+"/flush", nil)
	}
	return cmd
}

func (c *cmdFirewall) statsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stats",
		Short: "Show the xdpfw_stats per-CPU counters",
		RunE: func(_ *cobra.Command, _ []string) error {
			return c.do(http.MethodGet, NamePlugin+"/stats", nil)
		},
	}
}

func (c *cmdFirewall) metricsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "metrics",
		Short: "Show the xdpfw_metrics counters and xdpfw_perf histogram",
		RunE: func(_ *cobra.Command, _ []string) error {
			return c.do(http.MethodGet, NamePlugin+"/metrics", nil)
		},
	}
}

func (c *cmdFirewall) controlCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "control", Short: "Control the running bpf program"}
	bpf := &cobra.Command{Use: "bpf", Short: "Control bpf runtime options"}

	var on, off bool
	dryrun := &cobra.Command{
		Use:   "dryrun",
		Short: "Set or clear the runtime dryrun flag (count matches, do not drop)",
	}
	dryrun.Flags().BoolVar(&on, "on", false, "enable dryrun")
	dryrun.Flags().BoolVar(&off, "off", false, "disable dryrun (enforce)")
	dryrun.RunE = func(_ *cobra.Command, _ []string) error {
		if on == off {
			return fmt.Errorf("pass exactly one of --on / --off")
		}
		req := ControlBpfReq{Option: "dryrun", Value: on, Dryrun: c.dryrun}
		body, _ := json.Marshal(req)
		return c.do(http.MethodPost, NamePlugin+"/control/bpf", body)
	}

	bpf.AddCommand(dryrun)
	cmd.AddCommand(bpf)
	return cmd
}
