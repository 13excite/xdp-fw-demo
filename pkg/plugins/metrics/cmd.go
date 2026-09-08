package metrics

import (
	"fmt"

	"github.com/spf13/cobra"
)

// cmdMetrics implements the "xdpfw metrics" command tree which
// talks to the running daemon over its http api.
type cmdMetrics struct {
	p *TMetricsPlugin
}

func (c *cmdMetrics) Command() *cobra.Command {

	cmd := &cobra.Command{}
	cmd.Use = NamePlugin
	cmd.Short = "Show metrics exported by the running daemon"
	cmd.Long = "Fetch aggregated metrics from the running daemon via its api"

	showCmd := cmdMetricsShow{p: c.p}
	cmd.AddCommand(showCmd.Command())

	return cmd
}

type cmdMetricsShow struct {
	p *TMetricsPlugin
}

func (c *cmdMetricsShow) Command() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Use = "show [name]"
	cmd.Short = "Show all metrics or a single metric by name"
	cmd.Args = cobra.MaximumNArgs(1)
	cmd.RunE = c.Run
	return cmd
}

func (c *cmdMetricsShow) Run(cmd *cobra.Command, args []string) error {
	id := "(metrics) (cmd) (show)"

	name := ""
	if len(args) == 1 {
		name = args[0]
	}

	values, err := c.p.GetClientMetrics(name)
	if err != nil {
		c.p.G().L.Errorf("%s error requesting metrics, err:'%s'", id, err)
		return err
	}

	for _, v := range values {
		fmt.Printf("  %-24s %12.2f  tags:%v\n", v.ID, v.Value, v.Tags)
	}
	return nil
}
