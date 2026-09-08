package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/13excite/xdp-fw-demo/pkg/controller"
)

// peekFlag returns the value of -short / --long from the raw args,
// accepting both "-C path" and "-C=path" forms and any position.
// It is used before cobra is wired up so configuration and the
// logger can be built in init(); it never exits or prints.
func peekFlag(args []string, short, long string) string {
	forms := []string{"-" + short, "--" + long, "-" + long}
	for i := 0; i < len(args); i++ {
		a := args[i]
		for _, f := range forms {
			if a == f {
				if i+1 < len(args) {
					return args[i+1]
				}
				return ""
			}
			if strings.HasPrefix(a, f+"=") {
				return a[len(f)+1:]
			}
		}
	}
	return ""
}

func peekBool(args []string, short, long string) bool {
	for _, a := range args {
		if a == "-"+short || a == "--"+long || a == "-"+long {
			return true
		}
	}
	return false
}

var (
	// an instance of controller to configure and run
	c *controller.Controller

	// alternative configuration file from the command line
	configFile string

	// debug option, from the command line and configuration
	debug bool

	// log file, overrides the log path from configuration
	logFile string

	// root cmd, parent of every other command
	rootCmd = &cobra.Command{
		SilenceUsage: true,
		Use:          "xdpfw",
		Short:        "stateless XDP IPv4/IPv6 source-address firewall controller",
		Long: `xdpfw runs an XDP firewall as a long-lived service: it attaches the
bpf program, pins its maps, exposes an http api on /api/v1.0 and hosts
feature plugins (firewall, metrics). Runtime operations are issued as
subcommands that call the running daemon's api.`,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if err := c.CreateLogger(logFile, debug); err != nil {
				fmt.Printf("error creating log, err:'%s'\n", err)
				os.Exit(1)
			}
		},
	}
)

func Execute() error {
	return rootCmd.Execute()
}

func SetVersion(version string, revision string) {
	c.Runtime().Version = fmt.Sprintf("%s-r%s", strings.TrimRight(version, "\r\n"),
		strings.TrimRight(revision, "\r\n"))
}

func SetDate(date string) {
	c.Runtime().Date = strings.TrimRight(date, "\r\n")
}

func init() {

	// cobra flags are not parsed yet at this point, so grab -C / -L / -d
	// early (without hijacking --help) for config + logger
	args := os.Args[1:]
	earlyConfig := peekFlag(args, "C", "config")
	earlyLog := peekFlag(args, "L", "log")
	debug = peekBool(args, "d", "debug")

	// seed the cobra flag defaults from the early peek so an early
	// -d/--debug already raises the log level built in init()
	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "C", earlyConfig, "configuration file")
	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", debug,
		"debug output, default: 'false'")
	rootCmd.PersistentFlags().StringVarP(&logFile, "log", "L", earlyLog,
		"log file, default: 'stdout'")

	c = controller.NewController()

	var options controller.ConfigOptions
	options.ConfigFile = earlyConfig

	if err := c.LoadConfig(&options); err != nil {
		fmt.Printf("error loading configuration from:'%s', err:'%s'\n", options.ConfigFile, err)
		os.Exit(1)
	}

	logFile = earlyLog
	if err := c.CreateLogger(logFile, debug); err != nil {
		fmt.Printf("error creating log, err:'%s'\n", err)
		os.Exit(1)
	}

	// plugins register their own subcommands on rootCmd
	if err := c.CreatePlugins(&controller.PluginsOptions{Root: rootCmd}); err != nil {
		c.L().Errorf("error creating plugins, err:'%s'", err)
		os.Exit(1)
	}

	versionCmd := cmdVersion{g: c}
	rootCmd.AddCommand(versionCmd.Command())

	serverCmd := cmdServer{g: c}
	rootCmd.AddCommand(serverCmd.Command())
}
