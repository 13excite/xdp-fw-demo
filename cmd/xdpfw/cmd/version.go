package cmd

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/13excite/xdp-fw-demo/pkg/controller"
)

type cmdVersion struct {
	g *controller.Controller
}

func (c *cmdVersion) Command() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Use = "version"
	cmd.Short = "Show version and runtime information"
	cmd.Long = "Show the application version, build date and runtime options"
	cmd.RunE = c.Run
	return cmd
}

func (c *cmdVersion) Run(cmd *cobra.Command, args []string) error {
	fmt.Printf("%s: '%s', build date:'%s', compiler:'%s' '%s', host:'%s'\n",
		c.g.Runtime().ProgramName, c.g.Runtime().Version, c.g.Runtime().Date,
		runtime.Compiler, runtime.Version(), c.g.Runtime().Hostname)
	return nil
}
