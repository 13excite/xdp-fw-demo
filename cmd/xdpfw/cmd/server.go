package cmd

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	"github.com/13excite/xdp-fw-demo/pkg/controller"
)

type Switches struct {
	// alternative bpf object to override the one from config
	Bpf string
}

type cmdServer struct {
	g *controller.Controller

	switches Switches
}

func (c *cmdServer) Command() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Use = "server"
	cmd.Short = "Controlling the server process"
	cmd.Long = "Starting and stopping the long-lived server process"

	cmd.PersistentFlags().StringVarP(&c.switches.Bpf, "bpf", "B", "",
		"bpf: path to an alternative bpf object to load")

	serverStartCmd := cmdServerStart{g: c.g, s: c}
	cmd.AddCommand(serverStartCmd.Command())

	return cmd
}

type cmdServerStart struct {
	g *controller.Controller
	s *cmdServer
}

func (c *cmdServerStart) Command() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Use = "start"
	cmd.Short = "Starting the server"
	cmd.Long = "Attach the xdp program, serve the api and run plugins until interrupted"
	cmd.RunE = c.Run
	return cmd
}

func (c *cmdServerStart) Run(cmd *cobra.Command, args []string) error {
	id := "(server) (start)"
	c.g.L().Debugf("%s starting server version:'%s' date:'%s'", id,
		c.g.Runtime().Version, c.g.Runtime().Date)

	ctx := context.Background()
	w, ctx := errgroup.WithContext(ctx)

	w.Go(func() error {
		err := WaitInterrupted(ctx)
		c.g.L().Errorf("%s caught interruption, err:'%s'", id, err)
		return err
	})

	w.Go(func() error {
		var options controller.ControllerOptions
		options.Bpf = c.s.switches.Bpf
		return c.g.Run(ctx, &options)
	})

	return w.Wait()
}

// WaitInterrupted blocks until SIGINT/SIGTERM or ctx cancellation.
func WaitInterrupted(ctx context.Context) error {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	select {
	case v := <-sigChan:
		return errors.New(v.String())
	case <-ctx.Done():
		return ctx.Err()
	}
}
