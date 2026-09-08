package firewall

import (
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"

	"github.com/cilium/ebpf"
)

const (
	// default bpffs pin path for all firewall maps and
	// the pinned xdp link
	DefaultPinPath = "/sys/fs/bpf/xdpfw"
)

// stat slots in the xdpfw_stats per-CPU array
// (keep in sync with bpf/xdpfw.bpf.h)
const (
	StatPktsTotal = 0
	StatIPv4Match = 1
	StatIPv6Match = 2
	StatPassed    = 3
	StatSlots     = 8
)

// xdpfw_metrics counter indexes (keep in sync with bpf/xdpfw.bpf.h)
const (
	MetricRX       = 0
	MetricPass     = 1
	MetricDrop     = 2
	MetricError    = 3
	MetricAllowHit = 4
	MetricBlockV4  = 5
	MetricBlockV6  = 6

	MetricSlots = 64
)

// xdpfw_perf packet-size histogram
const PerfSlots = 64

// xdpfw_runtime_config indexes (keep in sync with bpf/xdpfw.bpf.h)
const (
	CfgDryrun = 0
	CfgSlots  = 16
)

// map names, must match bpf/xdpfw.bpf.c
const (
	MapBlockV4  = "blocklist_v4"
	MapBlockV6  = "blocklist_v6"
	MapAllowV4  = "allowlist_v4"
	MapAllowV6  = "allowlist_v6"
	MapStats    = "xdpfw_stats"
	MapMetrics  = "xdpfw_metrics"
	MapPerf     = "xdpfw_perf"
	MapRTConfig = "xdpfw_runtime_config"
)

// LpmKey4 / LpmKey6 are the LPM-trie keys: a u32 prefix length
// followed by the address bytes in network byte order.
type LpmKey4 struct {
	PrefixLen uint32
	Addr      [4]byte
}

type LpmKey6 struct {
	PrefixLen uint32
	Addr      [16]byte
}

func joinPin(root, name string) string {
	if len(root) == 0 {
		root = DefaultPinPath
	}
	return filepath.Join(root, name)
}

// ---------------------------------------------------------------------------
// prefix sets (blocklist / allowlist), each a pair of LPM-trie maps
// ---------------------------------------------------------------------------

type prefixMap struct {
	Mp      *ebpf.Map
	pinPath string
	name    string
	v6      bool
}

func (m *prefixMap) load() error {
	mp, err := ebpf.LoadPinnedMap(joinPin(m.pinPath, m.name), nil)
	if err != nil {
		return fmt.Errorf("open pinned map %s: %w (is the daemon running?)", m.name, err)
	}
	m.Mp = mp
	return nil
}

func (m *prefixMap) close() error {
	if m.Mp == nil {
		return nil
	}
	return m.Mp.Close()
}

func (m *prefixMap) update(p netip.Prefix) error {
	one := uint8(1)
	if m.v6 {
		k := LpmKey6{PrefixLen: uint32(p.Bits()), Addr: p.Addr().As16()}
		return m.Mp.Update(&k, &one, ebpf.UpdateAny)
	}
	k := LpmKey4{PrefixLen: uint32(p.Bits()), Addr: p.Addr().As4()}
	return m.Mp.Update(&k, &one, ebpf.UpdateAny)
}

func (m *prefixMap) remove(p netip.Prefix) error {
	if m.v6 {
		k := LpmKey6{PrefixLen: uint32(p.Bits()), Addr: p.Addr().As16()}
		return m.Mp.Delete(&k)
	}
	k := LpmKey4{PrefixLen: uint32(p.Bits()), Addr: p.Addr().As4()}
	return m.Mp.Delete(&k)
}

func (m *prefixMap) entries() ([]netip.Prefix, error) {
	var out []netip.Prefix
	var val uint8
	it := m.Mp.Iterate()
	if m.v6 {
		var k LpmKey6
		for it.Next(&k, &val) {
			out = append(out, netip.PrefixFrom(netip.AddrFrom16(k.Addr), int(k.PrefixLen)))
		}
	} else {
		var k LpmKey4
		for it.Next(&k, &val) {
			out = append(out, netip.PrefixFrom(netip.AddrFrom4(k.Addr), int(k.PrefixLen)))
		}
	}
	return out, it.Err()
}

func (m *prefixMap) flush() (int, error) {
	entries, err := m.entries()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, p := range entries {
		if err := m.remove(p); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return n, err
		}
		n++
	}
	return n, nil
}

// PrefixSet is a blocklist or an allowlist: an IPv4 LPM map and
// an IPv6 LPM map that are addressed together.
type PrefixSet struct {
	v4 prefixMap
	v6 prefixMap
}

func NewBlockSet(pin string) *PrefixSet {
	return &PrefixSet{
		v4: prefixMap{pinPath: pin, name: MapBlockV4, v6: false},
		v6: prefixMap{pinPath: pin, name: MapBlockV6, v6: true},
	}
}

func NewAllowSet(pin string) *PrefixSet {
	return &PrefixSet{
		v4: prefixMap{pinPath: pin, name: MapAllowV4, v6: false},
		v6: prefixMap{pinPath: pin, name: MapAllowV6, v6: true},
	}
}

func (s *PrefixSet) Open() error {
	if err := s.v4.load(); err != nil {
		return err
	}
	if err := s.v6.load(); err != nil {
		_ = s.v4.close()
		return err
	}
	return nil
}

func (s *PrefixSet) Close() error {
	err4 := s.v4.close()
	err6 := s.v6.close()
	if err4 != nil {
		return err4
	}
	return err6
}

func (s *PrefixSet) Add(p netip.Prefix) error {
	if p.Addr().Is6() {
		return s.v6.update(p)
	}
	return s.v4.update(p)
}

func (s *PrefixSet) Del(p netip.Prefix) error {
	if p.Addr().Is6() {
		return s.v6.remove(p)
	}
	return s.v4.remove(p)
}

// List returns the IPv4 entries followed by the IPv6 entries.
func (s *PrefixSet) List() ([]netip.Prefix, error) {
	e4, err := s.v4.entries()
	if err != nil {
		return nil, err
	}
	e6, err := s.v6.entries()
	if err != nil {
		return nil, err
	}
	return append(e4, e6...), nil
}

// Flush empties both maps and returns the number of IPv4 and
// IPv6 entries removed.
func (s *PrefixSet) Flush() (int, int, error) {
	n4, err := s.v4.flush()
	if err != nil {
		return n4, 0, err
	}
	n6, err := s.v6.flush()
	return n4, n6, err
}

// ---------------------------------------------------------------------------
// xdpfw_stats: per-CPU counters
// ---------------------------------------------------------------------------

type StatsMap struct {
	Mp      *ebpf.Map
	PinPath string
}

func (m *StatsMap) MapName() string { return MapStats }

func (m *StatsMap) Open() error {
	mp, err := ebpf.LoadPinnedMap(joinPin(m.PinPath, m.MapName()), nil)
	if err != nil {
		return fmt.Errorf("open pinned map %s: %w", m.MapName(), err)
	}
	m.Mp = mp
	return nil
}

func (m *StatsMap) Close() error {
	if m.Mp == nil {
		return nil
	}
	return m.Mp.Close()
}

// Entries returns the summed (over all CPUs) value of each
// labelled stat slot.
func (m *StatsMap) Entries() (map[string]uint64, error) {
	labels := []struct {
		idx  uint32
		name string
	}{
		{StatPktsTotal, "packets_total"},
		{StatIPv4Match, "ipv4_matched"},
		{StatIPv6Match, "ipv6_matched"},
		{StatPassed, "passed"},
	}

	out := make(map[string]uint64, len(labels))
	for _, l := range labels {
		var percpu []uint64
		if err := m.Mp.Lookup(&l.idx, &percpu); err != nil {
			return out, fmt.Errorf("read slot %d: %w", l.idx, err)
		}
		var sum uint64
		for _, v := range percpu {
			sum += v
		}
		out[l.name] = sum
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// xdpfw_metrics / xdpfw_perf: plain u64 arrays
// ---------------------------------------------------------------------------

type ArrayU64 struct {
	Mp      *ebpf.Map
	PinPath string
	name    string
}

func NewMetricsMap(pin string) *ArrayU64 { return &ArrayU64{PinPath: pin, name: MapMetrics} }
func NewPerfMap(pin string) *ArrayU64    { return &ArrayU64{PinPath: pin, name: MapPerf} }

func (m *ArrayU64) MapName() string { return m.name }

func (m *ArrayU64) Open() error {
	mp, err := ebpf.LoadPinnedMap(joinPin(m.PinPath, m.name), nil)
	if err != nil {
		return fmt.Errorf("open pinned map %s: %w", m.name, err)
	}
	m.Mp = mp
	return nil
}

func (m *ArrayU64) Close() error {
	if m.Mp == nil {
		return nil
	}
	return m.Mp.Close()
}

func (m *ArrayU64) Entries() ([MetricSlots]uint64, error) {
	var out [MetricSlots]uint64
	var (
		it    = m.Mp.Iterate()
		key   uint32
		value uint64
	)
	for it.Next(&key, &value) {
		if int(key) < len(out) {
			out[key] = value
		}
	}
	return out, it.Err()
}

func (m *ArrayU64) ZeroAll() error {
	zero := uint64(0)
	for k := uint32(0); k < MetricSlots; k++ {
		if err := m.Mp.Update(&k, &zero, ebpf.UpdateAny); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// xdpfw_runtime_config: u32 array, index 0 is the runtime dryrun flag
// ---------------------------------------------------------------------------

type RuntimeConfig struct {
	Mp      *ebpf.Map
	PinPath string
}

func (m *RuntimeConfig) MapName() string { return MapRTConfig }

func (m *RuntimeConfig) Open() error {
	mp, err := ebpf.LoadPinnedMap(joinPin(m.PinPath, m.MapName()), nil)
	if err != nil {
		return fmt.Errorf("open pinned map %s: %w", m.MapName(), err)
	}
	m.Mp = mp
	return nil
}

func (m *RuntimeConfig) Close() error {
	if m.Mp == nil {
		return nil
	}
	return m.Mp.Close()
}

func (m *RuntimeConfig) Update(key, value uint32) error {
	return m.Mp.Update(&key, &value, ebpf.UpdateAny)
}

func (m *RuntimeConfig) Entries() ([]uint32, error) {
	out := make([]uint32, 0, CfgSlots)
	var (
		it    = m.Mp.Iterate()
		key   uint32
		value uint32
	)
	for it.Next(&key, &value) {
		out = append(out, value)
	}
	return out, it.Err()
}

func (m *RuntimeConfig) SetDryrun(on bool) error {
	value := uint32(0)
	if on {
		value = 1
	}
	return m.Update(uint32(CfgDryrun), value)
}

func (m *RuntimeConfig) GetDryrun() (bool, error) {
	var value uint32
	key := uint32(CfgDryrun)
	if err := m.Mp.Lookup(&key, &value); err != nil {
		return false, err
	}
	return value != 0, nil
}
