package plugins

import (
	"context"

	"github.com/labstack/echo/v4"
	"github.com/spf13/cobra"

	"github.com/13excite/xdp-fw-demo/pkg/internal/config"
)

// OverrideOptions carries values that override configuration,
// supplied on the "server" command line.
type OverrideOptions struct {

	// bpf program path from command line
	Bpf string
}

type PluginOptions struct {
	// name and type of plugin
	Name string
	Type string

	// a part of configuration for plugin (re-marshalled yaml)
	Content []byte

	// a root cmd object to attach plugin commands to
	Root *cobra.Command

	// global reference to configuration
	Global *config.TGlobal

	// a plugins registry object
	Plugins *Plugins
}

// Plugin implements the common attributes shared by all plugins.
type Plugin struct {

	// general configuration
	g *config.TGlobal

	// a reference to the plugins registry
	plugins *Plugins

	// type and name of plugin
	t string

	// name should be one of the known plugin names
	name string
}

func (p *Plugin) Name() string {
	return p.name
}

func (p *Plugin) Type() string {
	return p.t
}

func (p *Plugin) G() *config.TGlobal {
	return p.g
}

func (p *Plugin) P() *Plugins {
	return p.plugins
}

func (p *Plugin) SetName(name string) {
	p.name = name
}

func (p *Plugin) SetType(t string) {
	p.t = t
}

func (p *Plugin) SetGlobal(g *config.TGlobal) {
	p.g = g
}

func (p *Plugin) SetPlugins(plugins *Plugins) {
	p.plugins = plugins
}

type IPlugin interface {
	// returning a name
	Name() string

	// run method for plugin
	Run(ctx context.Context, overrides *OverrideOptions) error

	// setting up api methods on the shared group
	SetupMethods(group *echo.Group)
}

type Plugins struct {
	g *config.TGlobal

	// map of plugins grouped by type name
	plugins map[string][]IPlugin
}

func NewPlugins(g *config.TGlobal) *Plugins {
	var p Plugins
	p.g = g
	p.plugins = make(map[string][]IPlugin)
	return &p
}

func (p *Plugins) AddPlugin(k string, plugin IPlugin) {
	p.plugins[k] = append(p.plugins[k], plugin)
}

func (p *Plugins) GetPlugins() []IPlugin {
	var out []IPlugin
	for _, plugin := range p.plugins {
		out = append(out, plugin...)
	}
	return out
}

func (p *Plugins) GetPlugin(name string) IPlugin {
	for _, plugin := range p.plugins {
		for _, p := range plugin {
			if p.Name() == name {
				return p
			}
		}
	}
	return nil
}

// M is a shortcut to the metrics plugin so other plugins can
// push metrics through it.
func (p *Plugins) M() IPlugin {
	return p.GetPlugin("metrics")
}
