package firewall

import (
	"fmt"
	"net/http"
	"net/netip"
	"sort"

	"github.com/labstack/echo/v4"
)

// request / response payloads shared with cmd.go (same package)

type EntriesReq struct {
	Entries []string `json:"entries"`
	Dryrun  bool     `json:"dryrun"`
}

type EntriesResp struct {
	Applied []string          `json:"applied"`
	Skipped []string          `json:"skipped,omitempty"`
	Errors  map[string]string `json:"errors,omitempty"`
}

type ListResp struct {
	Kind string   `json:"kind"`
	V4   []string `json:"v4"`
	V6   []string `json:"v6"`
}

type FlushResp struct {
	Kind string `json:"kind"`
	V4   int    `json:"v4"`
	V6   int    `json:"v6"`
}

type ControlBpfReq struct {
	Option string `json:"option"`
	Value  bool   `json:"value"`
	Dryrun bool   `json:"dryrun"`
}

const (
	kindBlock = "blocklist"
	kindAllow = "allowlist"
)

func (t *TFirewallPlugin) SetupMethods(group *echo.Group) {
	base := "/" + NamePlugin

	group.GET(base+"/ping", t.apiPing)

	for _, kind := range []string{kindBlock, kindAllow} {
		k := kind
		group.GET(base+"/"+k, func(ctx echo.Context) error { return t.apiList(ctx, k) })
		group.POST(base+"/"+k, func(ctx echo.Context) error { return t.apiAdd(ctx, k) })
		group.DELETE(base+"/"+k, func(ctx echo.Context) error { return t.apiDel(ctx, k) })
		group.POST(base+"/"+k+"/flush", func(ctx echo.Context) error { return t.apiFlush(ctx, k) })
	}

	group.GET(base+"/stats", t.apiStats)
	group.GET(base+"/metrics", t.apiMetrics)
	group.POST(base+"/control/bpf", t.apiControlBpf)
}

func (t *TFirewallPlugin) pin() string {
	pin := t.L().Options.PinPath
	if len(pin) == 0 {
		pin = DefaultPinPath
	}
	return pin
}

func (t *TFirewallPlugin) openSet(kind string) (*PrefixSet, error) {
	var s *PrefixSet
	switch kind {
	case kindAllow:
		s = NewAllowSet(t.pin())
	default:
		s = NewBlockSet(t.pin())
	}
	if err := s.Open(); err != nil {
		return nil, err
	}
	return s, nil
}

func (t *TFirewallPlugin) apiPing(ctx echo.Context) error {
	return ctx.String(http.StatusOK, "OK")
}

func (t *TFirewallPlugin) apiList(ctx echo.Context, kind string) error {
	id := "(firewall) (api) (list)"

	s, err := t.openSet(kind)
	if err != nil {
		t.G().L.Errorf("%s %s", id, err)
		return echo.NewHTTPError(http.StatusServiceUnavailable, err.Error())
	}
	defer s.Close()

	prefixes, err := s.List()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	resp := ListResp{Kind: kind, V4: []string{}, V6: []string{}}
	for _, p := range prefixes {
		if p.Addr().Is6() {
			resp.V6 = append(resp.V6, p.String())
		} else {
			resp.V4 = append(resp.V4, p.String())
		}
	}
	sort.Strings(resp.V4)
	sort.Strings(resp.V6)

	return ctx.JSONPretty(http.StatusOK, resp, "  ")
}

func (t *TFirewallPlugin) apiAdd(ctx echo.Context, kind string) error {
	return t.apiMutate(ctx, kind, true)
}

func (t *TFirewallPlugin) apiDel(ctx echo.Context, kind string) error {
	return t.apiMutate(ctx, kind, false)
}

func (t *TFirewallPlugin) apiMutate(ctx echo.Context, kind string, add bool) error {
	id := "(firewall) (api) (mutate)"

	var req EntriesReq
	if err := ctx.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	if len(req.Entries) == 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "no entries supplied")
	}

	// validate all entries before touching the maps
	parsed := make([]netip.Prefix, 0, len(req.Entries))
	resp := EntriesResp{Applied: []string{}, Errors: map[string]string{}}
	for _, e := range req.Entries {
		p, skip, err := ParseEntry(e)
		if err != nil {
			resp.Errors[e] = err.Error()
			continue
		}
		if skip {
			resp.Skipped = append(resp.Skipped, e)
			continue
		}
		parsed = append(parsed, p)
	}
	if len(resp.Errors) > 0 {
		return ctx.JSONPretty(http.StatusBadRequest, resp, "  ")
	}

	if req.Dryrun {
		for _, p := range parsed {
			resp.Applied = append(resp.Applied, p.String())
		}
		t.G().L.Debugf("%s dryrun %s add:'%t' entries:'%d'", id, kind, add, len(parsed))
		return ctx.JSONPretty(http.StatusOK, resp, "  ")
	}

	s, err := t.openSet(kind)
	if err != nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, err.Error())
	}
	defer s.Close()

	for _, p := range parsed {
		var opErr error
		if add {
			opErr = s.Add(p)
		} else {
			opErr = s.Del(p)
		}
		if opErr != nil {
			resp.Errors[p.String()] = opErr.Error()
			continue
		}
		resp.Applied = append(resp.Applied, p.String())
	}

	code := http.StatusOK
	if len(resp.Errors) > 0 {
		code = http.StatusMultiStatus
	}
	return ctx.JSONPretty(code, resp, "  ")
}

func (t *TFirewallPlugin) apiFlush(ctx echo.Context, kind string) error {
	s, err := t.openSet(kind)
	if err != nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, err.Error())
	}
	defer s.Close()

	n4, n6, err := s.Flush()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	return ctx.JSONPretty(http.StatusOK, FlushResp{Kind: kind, V4: n4, V6: n6}, "  ")
}

func (t *TFirewallPlugin) apiStats(ctx echo.Context) error {
	sm := &StatsMap{PinPath: t.pin()}
	if err := sm.Open(); err != nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, err.Error())
	}
	defer sm.Close()

	stats, err := sm.Entries()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	return ctx.JSONPretty(http.StatusOK, stats, "  ")
}

func (t *TFirewallPlugin) apiMetrics(ctx echo.Context) error {
	out := map[string]interface{}{}

	mc := NewMetricsMap(t.pin())
	if err := mc.Open(); err == nil {
		if vals, err := mc.Entries(); err == nil {
			out["metrics"] = map[string]uint64{
				"packets_rx":       vals[MetricRX],
				"packets_pass":     vals[MetricPass],
				"packets_drop":     vals[MetricDrop],
				"packets_error":    vals[MetricError],
				"allowlist_hit":    vals[MetricAllowHit],
				"blocklist_v4_hit": vals[MetricBlockV4],
				"blocklist_v6_hit": vals[MetricBlockV6],
			}
		}
		_ = mc.Close()
	}

	pm := NewPerfMap(t.pin())
	if err := pm.Open(); err == nil {
		if buckets, err := pm.Entries(); err == nil {
			out["perf"] = buckets
		}
		_ = pm.Close()
	}

	if len(out) == 0 {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "maps not ready")
	}
	return ctx.JSONPretty(http.StatusOK, out, "  ")
}

func (t *TFirewallPlugin) apiControlBpf(ctx echo.Context) error {
	id := "(firewall) (api) (control) (bpf)"

	var req ControlBpfReq
	if err := ctx.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	t.G().L.Debugf("%s option:'%s' value:'%t' dryrun:'%t'", id, req.Option, req.Value, req.Dryrun)

	if req.Dryrun {
		return echo.NewHTTPError(http.StatusBadRequest,
			fmt.Sprintf("request to set '%s'='%t' is a dryrun", req.Option, req.Value))
	}

	switch req.Option {
	case "dryrun":
		if t.xdp == nil {
			// fall back to opening the pinned map directly
			rc := &RuntimeConfig{PinPath: t.pin()}
			if err := rc.Open(); err != nil {
				return echo.NewHTTPError(http.StatusServiceUnavailable, err.Error())
			}
			defer rc.Close()
			if err := rc.SetDryrun(req.Value); err != nil {
				return echo.NewHTTPError(http.StatusServiceUnavailable, err.Error())
			}
		} else if err := t.xdp.SetDryrun(req.Value); err != nil {
			return echo.NewHTTPError(http.StatusServiceUnavailable, err.Error())
		}
	default:
		return echo.NewHTTPError(http.StatusBadRequest,
			fmt.Sprintf("unknown option '%s'", req.Option))
	}

	return ctx.String(http.StatusOK, "OK")
}
