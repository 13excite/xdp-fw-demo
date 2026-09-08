package firewall

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"

	"github.com/13excite/xdp-fw-demo/pkg/internal/config"
)

// allowed prefix lengths, enforced on insert (matches the
// original xdpfw CLI policy)
const (
	MinPrefixV4, MaxPrefixV4 = 16, 32
	MinPrefixV6, MaxPrefixV6 = 64, 128
)

// ParseEntry converts "1.2.3.0/24", "2001:db8::/64" or a bare
// address into a masked netip.Prefix, enforcing the allowed
// prefix range. skip is true for blank lines and "#" comments.
func ParseEntry(s string) (p netip.Prefix, skip bool, err error) {
	if i := strings.IndexByte(s, '#'); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Prefix{}, true, nil
	}

	if strings.ContainsRune(s, '/') {
		p, err = netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, false, err
		}
	} else {
		a, e := netip.ParseAddr(s)
		if e != nil {
			return netip.Prefix{}, false, fmt.Errorf("not an IP or CIDR: %v", e)
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}

	// normalise IPv4-in-IPv6 (e.g. ::ffff:1.2.3.4) to plain IPv4
	if p.Addr().Is4In6() {
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	p = p.Masked()

	bits := p.Bits()
	if p.Addr().Is4() {
		if bits < MinPrefixV4 || bits > MaxPrefixV4 {
			return netip.Prefix{}, false, fmt.Errorf(
				"IPv4 prefix /%d outside allowed /%d../%d", bits, MinPrefixV4, MaxPrefixV4)
		}
		return p, false, nil
	}

	if bits < MinPrefixV6 || bits > MaxPrefixV6 {
		return netip.Prefix{}, false, fmt.Errorf(
			"IPv6 prefix /%d outside allowed /%d../%d", bits, MinPrefixV6, MaxPrefixV6)
	}
	return p, false, nil
}

// ---------------------------------------------------------------------------
// environment prerequisites
// ---------------------------------------------------------------------------

// MountBpffs checks whether bpffs is mounted and mounts it at
// /sys/fs/bpf if not. Useful in containers where the OS did not
// mount it.
func (t *TFirewallPlugin) MountBpffs() error {
	id := "(firewall) (bpffs)"

	out, err := exec.Command("/usr/bin/cat", "/proc/mounts").CombinedOutput()
	if err != nil {
		t.G().L.DumpBytes(id, out, 0)
		return fmt.Errorf("read /proc/mounts: %w", err)
	}
	for _, row := range strings.Split(string(out), "\n") {
		if len(row) > 0 && strings.Contains(row, "bpf") {
			t.G().L.Debugf("%s bpffs already mounted: '%s'", id, row)
			return nil
		}
	}

	command := []string{"-t", "bpf", "bpf", "/sys/fs/bpf", "-o",
		"rw,nosuid,nodev,noexec,relatime,mode=700"}
	t.G().L.Debugf("%s mounting bpffs via mount %s", id, strings.Join(command, " "))
	if out, err = exec.Command("/usr/bin/mount", command...).CombinedOutput(); err != nil {
		t.G().L.DumpBytes(id, out, 0)
		return fmt.Errorf("mount bpffs: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// loader mode detection (primary vs secondary attach)
// ---------------------------------------------------------------------------

type tNetdev struct {
	Ifname string      `json:"ifname"`
	Xdp    interface{} `json:"xdp"`
}

// DetectLoaderMode inspects the interface and the configured hook
// pin path to decide whether we are the primary loader (attach the
// program to the interface) or a secondary one (register into an
// already-attached program's tail-call hook map).
func (t *TXdpService) DetectLoaderMode(netdev string) (int, error) {
	id := "(firewall) (loader)"

	pinpath := t.p.L().Loader.Hook.PinPath
	if len(pinpath) == 0 {
		// no hook configured, we are the primary loader
		return LoaderModePrimary, nil
	}

	pinexists := config.Exists(pinpath)
	t.p.G().L.Debugf("%s hook pinpath:'%s' exists:'%t'", id, pinpath, pinexists)

	content, err := exec.Command("/usr/sbin/ip", "-j", "link", "list", "dev", netdev).CombinedOutput()
	if err != nil {
		t.p.G().L.DumpBytes(id, content, 0)
		return LoaderModePrimary, fmt.Errorf("ip link list %s: %w", netdev, err)
	}

	var configs []tNetdev
	if err = json.Unmarshal(content, &configs); err != nil {
		return LoaderModePrimary, fmt.Errorf("parse ip link json: %w", err)
	}
	if len(configs) == 0 {
		return LoaderModePrimary, fmt.Errorf("no configuration found for dev:'%s'", netdev)
	}

	xdploaded := configs[0].Xdp != nil
	t.p.G().L.Debugf("%s dev:'%s' xdp loaded:'%t'", id, netdev, xdploaded)

	if pinexists && xdploaded {
		return LoaderModeSecondary, nil
	}
	return LoaderModePrimary, nil
}
