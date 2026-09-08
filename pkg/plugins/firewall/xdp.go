package firewall

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sync/errgroup"
)

const (
	// default interface if none configured
	DefaultInterface = "lo"

	// default compiled bpf object
	DefaultPath = "bpf/xdpfw.bpf.o"

	// program name inside the bpf object
	ProgFunc = "xdp_fw"

	// bpf const names set at load time via the variables api
	ConstDryRun         = "xdpfw_dry_run"
	ConstMetricsEnabled = "xdpfw_metrics_enabled"
	ConstPerfEnabled    = "xdpfw_perf_enabled"

	// loader modes
	LoaderModePrimary   = 100
	LoaderModeSecondary = 101

	LoaderConfigPrimary   = "primary"
	LoaderConfigSecondary = "secondary"
	LoaderConfigAuto      = "auto"
)

func LoaderModeAsString(mode int) string {
	switch mode {
	case LoaderModePrimary:
		return "primary"
	case LoaderModeSecondary:
		return "secondary"
	}
	return "unknown"
}

// TXdpBinary is the target of ebpf.CollectionSpec.LoadAndAssign:
// the program plus every map we care about.
type TXdpBinary struct {
	Program *ebpf.Program `ebpf:"xdp_fw"`

	BlockV4 *ebpf.Map `ebpf:"blocklist_v4"`
	BlockV6 *ebpf.Map `ebpf:"blocklist_v6"`
	AllowV4 *ebpf.Map `ebpf:"allowlist_v4"`
	AllowV6 *ebpf.Map `ebpf:"allowlist_v6"`
	Stats   *ebpf.Map `ebpf:"xdpfw_stats"`
	Metrics *ebpf.Map `ebpf:"xdpfw_metrics"`
	Perf    *ebpf.Map `ebpf:"xdpfw_perf"`
	Config  *ebpf.Map `ebpf:"xdpfw_runtime_config"`
}

func (b *TXdpBinary) Close() {
	for _, c := range []interface{ Close() error }{
		b.Program, b.BlockV4, b.BlockV6, b.AllowV4, b.AllowV6,
		b.Stats, b.Metrics, b.Perf, b.Config,
	} {
		if c != nil {
			_ = c.Close()
		}
	}
}

type TXdpService struct {
	binary *TXdpBinary

	// options from configuration
	options *TConfigOptions

	// resolved loader mode
	mode int

	// ref to plugin
	p *TFirewallPlugin
}

func NewXdpService(p *TFirewallPlugin) (*TXdpService, error) {
	id := "(firewall) (xdp) (service)"

	var xdp TXdpService
	xdp.p = p

	options := p.L().Options
	xdp.options = &options

	if len(xdp.options.Interface) == 0 {
		xdp.options.Interface = DefaultInterface
	}
	if len(xdp.options.PinPath) == 0 {
		xdp.options.PinPath = DefaultPinPath
	}
	if len(xdp.options.Path) == 0 {
		xdp.options.Path = DefaultPath
	}

	// resolve loader mode against the environment
	detected, err := xdp.DetectLoaderMode(xdp.options.Interface)
	if err != nil {
		p.G().L.Errorf("%s error detecting loader mode, err:'%s'", id, err)
		return nil, err
	}

	switch p.L().Loader.Mode {
	case LoaderConfigPrimary:
		if detected != LoaderModePrimary {
			return nil, fmt.Errorf("loader config mode:'primary' failed (detected '%s')",
				LoaderModeAsString(detected))
		}
		xdp.mode = LoaderModePrimary
	case LoaderConfigSecondary:
		if detected != LoaderModeSecondary {
			return nil, fmt.Errorf("loader config mode:'secondary' failed (detected '%s')",
				LoaderModeAsString(detected))
		}
		xdp.mode = LoaderModeSecondary
	case LoaderConfigAuto, "":
		xdp.mode = detected
	default:
		return nil, fmt.Errorf("loader config mode:'%s' not supported", p.L().Loader.Mode)
	}

	p.G().L.Debugf("%s mode:'%s' interface:'%s' path:'%s' %s", id,
		LoaderModeAsString(xdp.mode), xdp.options.Interface, xdp.options.Path,
		xdp.options.String())

	if err = os.MkdirAll(xdp.options.PinPath, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w (is bpffs mounted at /sys/fs/bpf ?)",
			xdp.options.PinPath, err)
	}

	spec, err := ebpf.LoadCollectionSpec(xdp.options.Path)
	if err != nil {
		return nil, fmt.Errorf("load %s: %w", xdp.options.Path, err)
	}

	// set load-time constants through the variables api
	consts := map[string]uint8{
		ConstDryRun:         b2u8(xdp.options.DryRun),
		ConstMetricsEnabled: b2u8(xdp.options.Metrics),
		ConstPerfEnabled:    b2u8(xdp.options.Perf),
	}
	for name, v := range consts {
		vs := spec.Variables[name]
		if vs == nil {
			return nil, fmt.Errorf("object has no %s variable; rebuild bpf/", name)
		}
		if err = vs.Set(v); err != nil {
			return nil, fmt.Errorf("set const %s: %w", name, err)
		}
		p.G().L.Debugf("%s const %s = %d", id, name, v)
	}

	// verify the maps we depend on are present
	required := []string{
		MapBlockV4, MapBlockV6, MapAllowV4, MapAllowV6,
		MapStats, MapMetrics, MapPerf, MapRTConfig,
	}
	for _, n := range required {
		if _, ok := spec.Maps[n]; !ok {
			return nil, fmt.Errorf("bpf object has no map:'%s'", n)
		}
	}

	var binary TXdpBinary
	opts := ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: xdp.options.PinPath},
	}
	if err = spec.LoadAndAssign(&binary, &opts); err != nil {
		return nil, fmt.Errorf("load objects: %w", err)
	}
	xdp.binary = &binary

	// seed the runtime dryrun flag from configuration
	if err = xdp.SetDryrun(xdp.options.DryRun); err != nil {
		binary.Close()
		return nil, fmt.Errorf("seed runtime dryrun: %w", err)
	}

	p.G().L.Debugf("%s bpf:'%s' loaded OK", id, xdp.options.Path)
	return &xdp, nil
}

func (t *TXdpService) linkPath() string {
	return filepath.Join(t.options.PinPath, "link_"+t.options.Interface)
}

// Run attaches the program (primary) or registers it into an
// existing hook map (secondary) and blocks until ctx is done.
func (t *TXdpService) Run(ctx context.Context) error {
	id := "(firewall) (xdp) (run)"

	dev, err := net.InterfaceByName(t.options.Interface)
	if err != nil {
		return fmt.Errorf("interface %q: %w", t.options.Interface, err)
	}

	w, ctx := errgroup.WithContext(ctx)
	w.Go(func() error {
		switch t.mode {
		case LoaderModePrimary:
			l, err := link.AttachXDP(link.XDPOptions{
				Program:   t.binary.Program,
				Interface: dev.Index,
				Flags:     link.XDPGenericMode,
			})
			if err != nil {
				return fmt.Errorf("attach XDP to %s: %w (another XDP program attached, "+
					"or the driver has no native XDP)", t.options.Interface, err)
			}

			_ = os.Remove(t.linkPath())
			if err = l.Pin(t.linkPath()); err != nil {
				_ = l.Close()
				return fmt.Errorf("pin link %s: %w", t.linkPath(), err)
			}
			t.p.G().L.Debugf("%s attached %s to %s, link pinned at %s",
				id, ProgFunc, t.options.Interface, t.linkPath())

			defer func() {
				if err := l.Unpin(); err != nil {
					t.p.G().L.Errorf("%s error unpinning link, err:'%s'", id, err)
				}
				if err := l.Close(); err != nil {
					t.p.G().L.Errorf("%s error detaching xdp, err:'%s'", id, err)
					return
				}
				t.p.G().L.Debugf("%s xdp detached from %s OK", id, t.options.Interface)
			}()

		case LoaderModeSecondary:
			hookPath := t.p.L().Loader.Hook.PinPath
			hook, err := ebpf.LoadPinnedMap(hookPath, nil)
			if err != nil {
				return fmt.Errorf("load hook map %s: %w", hookPath, err)
			}
			defer hook.Close()

			for _, index := range t.p.L().Loader.Hook.Index {
				if err = hook.Put(int32(index), int32(t.binary.Program.FD())); err != nil {
					return fmt.Errorf("attach prog to hook index %d: %w", index, err)
				}
				t.p.G().L.Debugf("%s attached prog fd to hook index:'%d'", id, index)
			}
		}

		t.p.G().L.Debugf("%s bpf:'%s' on:'%s' waiting...", id, t.options.Path, t.options.Interface)
		<-ctx.Done()
		return nil
	})

	return w.Wait()
}

func (t *TXdpService) Stop() error {
	id := "(firewall) (xdp) (stop)"
	t.p.G().L.Debugf("%s stopping service", id)
	if t.binary != nil {
		t.binary.Close()
	}
	return nil
}

// SetDryrun / GetDryrun operate on the live xdpfw_runtime_config map.
func (t *TXdpService) SetDryrun(on bool) error {
	rc := RuntimeConfig{Mp: t.binary.Config}
	return rc.SetDryrun(on)
}

func (t *TXdpService) GetDryrun() (bool, error) {
	rc := RuntimeConfig{Mp: t.binary.Config}
	return rc.GetDryrun()
}

func b2u8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}
