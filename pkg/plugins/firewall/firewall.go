package firewall

// firewall plugin implements the bpf/xdp program handler:
// load and unload the program, expose bpf maps as an api and
// drive runtime configuration (dryrun).

import (
	"fmt"
	"strings"

	yaml "gopkg.in/yaml.v3"

	"github.com/13excite/xdp-fw-demo/pkg/plugins"
)

const (
	// plugin name is used by controller to link
	// code and configuration
	NamePlugin = "firewall"

	// tick interval for pushing bpf counters into the
	// metrics plugin, in seconds
	DefaultWatcherInterval = 20
)

type TFirewallPluginConfig struct {
	// could be disabled
	Enabled bool `json:"enabled" yaml:"enabled"`

	// bpf controls for some environments
	Controls TConfigControls `json:"controls" yaml:"controls"`

	// bpf xdp options
	Options TConfigOptions `json:"options" yaml:"options"`

	// XDP loader options, by default we have primary mode
	Loader TConfigLoader `json:"loader" yaml:"loader"`
}

type TConfigControls struct {
	// if controller should check and mount bpffs
	Bpffs bool `json:"bpffs" yaml:"bpffs"`

	// if we should set memlock to unlimited
	UnlimitMemlock bool `json:"unlimit-memlock" yaml:"unlimit-memlock"`
}

type TConfigOptions struct {
	// interface to attach the xdp program to
	Interface string `json:"interface" yaml:"interface"`

	// path to the compiled bpf object
	Path string `json:"path" yaml:"path"`

	// bpffs pin path for maps and the pinned link
	PinPath string `json:"pinpath" yaml:"pinpath"`

	// load-time dryrun: count matches but never drop
	DryRun bool `json:"dryrun" yaml:"dryrun"`

	// enable the xdpfw_metrics counters map
	Metrics bool `json:"metrics" yaml:"metrics"`

	// enable the xdpfw_perf packet-size histogram
	Perf bool `json:"perf" yaml:"perf"`
}

func (t *TConfigOptions) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "interface:'%s',", t.Interface)
	fmt.Fprintf(&b, "path:'%s',", t.Path)
	fmt.Fprintf(&b, "pinpath:'%s',", t.PinPath)
	fmt.Fprintf(&b, "dryrun:'%t',", t.DryRun)
	fmt.Fprintf(&b, "metrics:'%t',", t.Metrics)
	fmt.Fprintf(&b, "perf:'%t'", t.Perf)
	return b.String()
}

type TConfigLoader struct {
	// mode could be "primary", "secondary" or "auto"
	Mode string `json:"mode" yaml:"mode"`

	// hook options for "secondary" mode
	Hook THookLoader `json:"hook" yaml:"hook"`
}

type THookLoader struct {
	// hook map pin path
	PinPath string `json:"pinpath" yaml:"pinpath"`

	// hook indexes to attach the program fd to
	Index []int `json:"index" yaml:"index"`
}

type TFirewallPlugin struct {

	// some common attributes for all plugins, global
	// configuration ref, name and type
	plugins.Plugin

	// plugin configuration
	c *TFirewallPluginConfig

	// xdp service
	xdp *TXdpService
}

func (t *TFirewallPlugin) L() *TFirewallPluginConfig {
	return t.c
}

func (t *TFirewallPlugin) GetXdpService() *TXdpService {
	return t.xdp
}

func NewPlugin(options *plugins.PluginOptions) (*TFirewallPlugin, error) {

	id := NamePlugin

	var a TFirewallPlugin

	a.SetName(options.Name)
	a.SetType(options.Type)
	a.SetGlobal(options.Global)
	a.SetPlugins(options.Plugins)

	var c TFirewallPluginConfig
	if err := yaml.Unmarshal(options.Content, &c); err != nil {
		a.G().L.Errorf("%s error configuring plugin, err:'%s'", id, err)
		return nil, err
	}

	if !c.Enabled {
		err := fmt.Errorf("plugin:'%s' disabled", options.Name)
		a.G().L.Errorf("%s plugin is disabled, err:'%s'", id, err)
		return nil, err
	}
	a.c = &c

	// adding command line processing (if any)
	if options.Root != nil {
		cmd := cmdFirewall{p: &a}
		options.Root.AddCommand(cmd.Command())
	}

	return &a, nil
}
