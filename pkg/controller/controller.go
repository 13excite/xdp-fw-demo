package controller

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
	yaml "gopkg.in/yaml.v3"

	"github.com/13excite/xdp-fw-demo/pkg/internal/api"
	"github.com/13excite/xdp-fw-demo/pkg/internal/config"
	"github.com/13excite/xdp-fw-demo/pkg/internal/log"
	"github.com/13excite/xdp-fw-demo/pkg/plugins"
	"github.com/13excite/xdp-fw-demo/pkg/plugins/firewall"
	"github.com/13excite/xdp-fw-demo/pkg/plugins/metrics"
)

type ControllerOptions struct {
	// override bpf object path from the command line
	Bpf string
}

// Controller wires configuration, logging, the http api and the
// feature plugins together and runs them under one errgroup.
type Controller struct {
	g *config.TGlobal

	// api controller worker
	api *api.Server

	// registry of plugins
	plugins *plugins.Plugins

	mutex sync.Mutex
}

func (c *Controller) Runtime() *config.TRuntime { return c.g.Runtime }
func (c *Controller) L() *log.Logger            { return c.g.L }
func (c *Controller) O() *config.TConfig        { return c.g.Opts }

type ConfigOptions struct {
	LogFile    string
	Debug      bool
	ConfigFile string
}

func NewController() *Controller {
	var c Controller
	var g config.TGlobal
	var r config.TRuntime

	r.ProgramName = config.ProgramName
	r.Hostname, _ = os.Hostname()

	g.Runtime = &r
	c.g = &g

	c.plugins = plugins.NewPlugins(c.g)
	return &c
}

func (c *Controller) LoadConfig(options *ConfigOptions) error {
	id := "(controller) (config)"
	var err error

	ConfigFile := ""
	if options != nil && len(options.ConfigFile) > 0 {
		ConfigFile = options.ConfigFile
	}

	if c.g.Opts, err = config.NewConfig(ConfigFile, c.g.L); err != nil {
		if c.L() != nil {
			c.L().Errorf("%s error loading config:'%s', err:'%s'", id, ConfigFile, err)
		}
		return err
	}
	return nil
}

func (c *Controller) CreateLogger(filename string, debug bool) error {
	var err error

	var opts log.LoggerOptions
	opts.Debug = debug
	opts.Path = filename
	opts.Stdout = len(opts.Path) == 0

	opts.MaxAge = c.O().Log.MaxAge
	opts.MaxSize = c.O().Log.MaxSize
	opts.MaxBackups = c.O().Log.MaxBackups
	opts.Compression = c.O().Log.Compression

	if c.g.L, err = c.g.CreateLogger(&opts); err != nil {
		return err
	}
	return nil
}

type PluginsOptions struct {
	// root cmd to export plugin subcommands into
	Root *cobra.Command
}

// CreatePlugins instantiates the plugins declared in the
// configuration. Plugin types map to config sections; plugin
// names select the concrete constructor.
func (c *Controller) CreatePlugins(opts *PluginsOptions) error {
	id := "(controller) (plugins)"
	var err error

	types := []string{"monitoring", "bpf"}

	for _, k := range types {
		if _, ok := c.g.Opts.Plugins[k]; !ok {
			continue
		}
		for n, p := range c.g.Opts.Plugins[k] {

			if !config.StringInSlice(k, types) {
				err = fmt.Errorf("incorrect type:'%s', expecting one of ['%s']",
					k, strings.Join(types, ","))
				c.L().Errorf("%s error init plugin name:'%s', err:'%s'", id, k, err)
				return err
			}

			content, err := yaml.Marshal(p)
			if err != nil {
				c.L().Errorf("%s error marshalling plugin configuration, err:'%s'", id, err)
				return err
			}

			var plugin plugins.IPlugin

			var options plugins.PluginOptions
			options.Root = opts.Root
			options.Type = k
			options.Name = n
			options.Content = content
			options.Global = c.g
			options.Plugins = c.plugins

			switch n {
			case metrics.NamePlugin:
				if plugin, err = metrics.NewPlugin(&options); err != nil {
					c.L().Errorf("%s error configuring plugin name:'%s', err:'%s'", id, n, err)
					continue
				}
			case firewall.NamePlugin:
				if plugin, err = firewall.NewPlugin(&options); err != nil {
					c.L().Errorf("%s error configuring plugin name:'%s', err:'%s'", id, n, err)
					continue
				}
			default:
				c.L().Errorf("%s plugin type:'%s' name:'%s' is not implemented", id, k, n)
				continue
			}

			c.L().Debugf("%s config plugin k:'%s' name:'%s'", id, k, plugin.Name())
			c.plugins.AddPlugin(k, plugin)
		}
	}

	return nil
}

func (c *Controller) Run(ctx context.Context, options *ControllerOptions) error {
	id := "(controller) (run)"

	w, ctx := errgroup.WithContext(ctx)

	c.L().Debugf("%s running controller worker", id)

	var overrides plugins.OverrideOptions
	if options != nil {
		overrides.Bpf = options.Bpf
	}

	// http api web server, shared echo group for plugin methods
	c.api = api.NewServer(c.g)
	group := c.api.GetGroup()

	list := c.plugins.GetPlugins()
	for _, p := range list {
		p.SetupMethods(group)
	}

	w.Go(func() error {
		return c.api.Run(ctx)
	})

	for i := range list {
		p := list[i]
		c.L().Debugf("%s run plugin:'%s'", id, p.Name())
		w.Go(func() error {
			return p.Run(ctx, &overrides)
		})
	}

	return w.Wait()
}
