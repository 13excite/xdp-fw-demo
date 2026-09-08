package firewall

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"

	"github.com/13excite/xdp-fw-demo/pkg/plugins"
	"github.com/13excite/xdp-fw-demo/pkg/plugins/metrics"
)

func (t *TFirewallPlugin) Run(ctx context.Context, overrides *plugins.OverrideOptions) error {
	id := "(firewall) (run)"

	if overrides != nil && len(overrides.Bpf) > 0 {
		t.c.Options.Path = overrides.Bpf
	}

	t.G().L.Debugf("%s starting", id)

	controls := t.L().Controls
	if controls.Bpffs {
		t.G().L.Debugf("%s requesting bpf fs mount", id)
		if err := t.MountBpffs(); err != nil {
			t.G().L.Errorf("%s error mounting bpffs, err:'%s'", id, err)
			return err
		}
	}

	if controls.UnlimitMemlock {
		t.G().L.Debugf("%s requesting unlimited memlock", id)
		if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
			Cur: unix.RLIM_INFINITY,
			Max: unix.RLIM_INFINITY,
		}); err != nil {
			t.G().L.Errorf("%s failed to set rlimit memlock, err:'%s'", id, err)
			return err
		}
	}

	var err error
	if t.xdp, err = NewXdpService(t); err != nil {
		t.G().L.Errorf("%s error creating xdp service, err:'%s'", id, err)
		return err
	}

	w, ctx := errgroup.WithContext(ctx)

	// main XDP thread: attach + hold until ctx is done, then detach
	w.Go(func() error {
		t.G().L.Debugf("%s starting worker", id)
		defer t.G().L.Debugf("%s worker stopped", id)
		defer func() {
			if err := t.Stop(); err != nil {
				t.G().L.Debugf("%s error closing worker program, err:'%s'", id, err)
			}
		}()
		return t.xdp.Run(ctx)
	})

	// periodic task: pull bpf counters into the metrics plugin
	w.Go(func() error {
		return t.TickServer(ctx)
	})

	return w.Wait()
}

func (t *TFirewallPlugin) Stop() error {
	if t.xdp != nil {
		return t.xdp.Stop()
	}
	return nil
}

// TickServer periodically reads the xdpfw_metrics / xdpfw_perf /
// xdpfw_stats maps and pushes their values into the metrics plugin
// as counters.
func (t *TFirewallPlugin) TickServer(ctx context.Context) error {
	id := "(firewall) (tick)"

	timer := time.NewTicker(time.Duration(DefaultWatcherInterval) * time.Second)
	defer timer.Stop()

	pin := t.L().Options.PinPath

	counter := 0
	for {
		select {
		case <-timer.C:
			t.G().L.Debugf("%s tick counter:'%d'", id, counter)
			t.pushBpfMetrics(id, pin)
			counter++

		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (t *TFirewallPlugin) pushBpfMetrics(id, pin string) {
	m, ok := t.P().M().(*metrics.TMetricsPlugin)
	if !ok || m == nil {
		return
	}

	push := func(name string, v float64) {
		m.Push(metrics.MetricsCounter,
			[]string{fmt.Sprintf("name=%s", name), "type=firewall"}, v)
	}

	// xdpfw_metrics counters
	mc := NewMetricsMap(pin)
	if err := mc.Open(); err != nil {
		t.G().L.Debugf("%s metrics map not ready, err:'%s'", id, err)
	} else {
		vals, err := mc.Entries()
		_ = mc.Close()
		if err == nil {
			push("packets_rx", float64(vals[MetricRX]))
			push("packets_pass", float64(vals[MetricPass]))
			push("packets_drop", float64(vals[MetricDrop]))
			push("packets_error", float64(vals[MetricError]))
			push("allowlist_hit", float64(vals[MetricAllowHit]))
			push("blocklist_v4_hit", float64(vals[MetricBlockV4]))
			push("blocklist_v6_hit", float64(vals[MetricBlockV6]))
		}
	}

	// xdpfw_stats per-CPU counters
	sm := &StatsMap{PinPath: pin}
	if err := sm.Open(); err == nil {
		if stats, err := sm.Entries(); err == nil {
			for k, v := range stats {
				push("stats_"+k, float64(v))
			}
		}
		_ = sm.Close()
	}

	// xdpfw_perf histogram: export a single "total packets seen" sum
	pm := NewPerfMap(pin)
	if err := pm.Open(); err == nil {
		if buckets, err := pm.Entries(); err == nil {
			var sum uint64
			for _, b := range buckets {
				sum += b
			}
			push("perf_samples", float64(sum))
		}
		_ = pm.Close()
	}
}
