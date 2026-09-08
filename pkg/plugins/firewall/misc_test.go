package firewall

import "testing"

func TestParseEntry(t *testing.T) {
	tests := []struct {
		in     string
		want   string // masked prefix, or "" when skip/err expected
		skip   bool
		hasErr bool
	}{
		{in: "", skip: true},
		{in: "   # a comment", skip: true},
		{in: "203.0.113.7", want: "203.0.113.7/32"},
		{in: "198.51.100.0/24", want: "198.51.100.0/24"},
		{in: "10.13.5.7/16", want: "10.13.0.0/16"}, // masked
		{in: "2001:db8:dead:beef::1", want: "2001:db8:dead:beef::1/128"},
		{in: "2001:db8:1234::/64", want: "2001:db8:1234::/64"},
		{in: "::ffff:1.2.3.4", want: "1.2.3.4/32"}, // 4-in-6 unmapped
		{in: "10.0.0.0/8", hasErr: true},           // broader than /16
		{in: "2001:db8::/48", hasErr: true},        // broader than /64
		{in: "not-an-ip", hasErr: true},
	}

	for _, tc := range tests {
		p, skip, err := ParseEntry(tc.in)
		if tc.hasErr {
			if err == nil {
				t.Errorf("ParseEntry(%q): want error, got %v", tc.in, p)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseEntry(%q): unexpected error: %v", tc.in, err)
			continue
		}
		if skip != tc.skip {
			t.Errorf("ParseEntry(%q): skip = %v, want %v", tc.in, skip, tc.skip)
			continue
		}
		if tc.skip {
			continue
		}
		if got := p.String(); got != tc.want {
			t.Errorf("ParseEntry(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
