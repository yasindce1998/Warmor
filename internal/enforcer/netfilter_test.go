package enforcer

import (
	"sync"
	"testing"
	"time"
)

func TestNetFilterBlocklist(t *testing.T) {
	nf, err := NewNetFilter(NetFilterConfig{
		BlockCIDRs: []string{"10.0.0.0/8", "192.168.1.0/24", "fd00::1"},
	})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		addr    string
		blocked bool
	}{
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"192.168.1.50", true},
		{"192.168.2.1", false},
		{"8.8.8.8", false},
		{"172.16.0.1", false},
		{"fd00::1", true},
		{"fd00::2", false},
	}

	for _, tc := range tests {
		if got := nf.IsBlocked(tc.addr); got != tc.blocked {
			t.Errorf("IsBlocked(%s) = %v, want %v", tc.addr, got, tc.blocked)
		}
	}
}

func TestNetFilterBlocklistHostPort(t *testing.T) {
	nf, err := NewNetFilter(NetFilterConfig{
		BlockCIDRs: []string{"10.0.0.0/8"},
	})
	if err != nil {
		t.Fatal(err)
	}

	if !nf.IsBlocked("10.0.0.1:443") {
		t.Error("expected host:port format to be blocked")
	}
	if nf.IsBlocked("8.8.8.8:53") {
		t.Error("expected 8.8.8.8:53 to not be blocked")
	}
}

func TestNetFilterRateLimit(t *testing.T) {
	nf, err := NewNetFilter(NetFilterConfig{
		RateLimit: 5,
		Window:    100 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	pid := uint32(1234)

	// First 5 connections should be fine
	for i := range 5 {
		if nf.CheckRateLimit(pid) {
			t.Fatalf("rate limit hit on connection %d, expected to pass", i+1)
		}
	}

	// 6th should be rate-limited
	if !nf.CheckRateLimit(pid) {
		t.Error("expected rate limit to trigger on 6th connection")
	}

	// After window expires, should reset
	time.Sleep(150 * time.Millisecond)
	if nf.CheckRateLimit(pid) {
		t.Error("expected rate limit to reset after window")
	}
}

func TestNetFilterRateLimitDisabled(t *testing.T) {
	nf, err := NewNetFilter(NetFilterConfig{
		RateLimit: 0,
	})
	if err != nil {
		t.Fatal(err)
	}

	for range 100 {
		if nf.CheckRateLimit(1234) {
			t.Fatal("rate limit should never trigger when disabled")
		}
	}
}

func TestNetFilterDynamicAdd(t *testing.T) {
	nf, err := NewNetFilter(NetFilterConfig{})
	if err != nil {
		t.Fatal(err)
	}

	if nf.IsBlocked("10.0.0.1") {
		t.Fatal("nothing should be blocked initially")
	}

	if err := nf.AddCIDR("10.0.0.0/8"); err != nil {
		t.Fatal(err)
	}

	if !nf.IsBlocked("10.0.0.1") {
		t.Error("expected 10.0.0.1 to be blocked after adding CIDR")
	}
	if nf.BlocklistSize() != 1 {
		t.Errorf("expected blocklist size 1, got %d", nf.BlocklistSize())
	}
}

func TestNetFilterInvalidCIDR(t *testing.T) {
	_, err := NewNetFilter(NetFilterConfig{
		BlockCIDRs: []string{"not-a-cidr"},
	})
	if err == nil {
		t.Error("expected error for invalid CIDR")
	}
}

func TestNetFilterCleanup(t *testing.T) {
	nf, err := NewNetFilter(NetFilterConfig{
		RateLimit: 10,
		Window:    50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	nf.CheckRateLimit(100)
	nf.CheckRateLimit(200)
	nf.CheckRateLimit(300)

	time.Sleep(100 * time.Millisecond)
	nf.CleanupStale()

	nf.mu.RLock()
	count := len(nf.connCounts)
	nf.mu.RUnlock()
	if count != 0 {
		t.Errorf("expected 0 entries after cleanup, got %d", count)
	}
}

func TestNetFilterSingleIPEntries(t *testing.T) {
	nf, err := NewNetFilter(NetFilterConfig{BlockCIDRs: []string{"1.2.3.4"}})
	if err != nil {
		t.Fatal(err)
	}
	if !nf.IsBlocked("1.2.3.4") || nf.IsBlocked("1.2.3.5") {
		t.Error("bare IPv4 entry should block exactly that /32")
	}

	if err := nf.AddCIDR("2001:db8::1"); err != nil {
		t.Fatal(err)
	}
	if err := nf.AddCIDR("5.6.7.8"); err != nil {
		t.Fatal(err)
	}
	if !nf.IsBlocked("2001:db8::1") || nf.IsBlocked("2001:db8::2") {
		t.Error("bare IPv6 entry should block exactly that /128")
	}
	if !nf.IsBlocked("[2001:db8::1]:443") {
		t.Error("bracketed IPv6 host:port should be blocked")
	}
	if !nf.IsBlocked("5.6.7.8") {
		t.Error("dynamically added IPv4 should be blocked")
	}
	if nf.BlocklistSize() != 3 {
		t.Errorf("BlocklistSize = %d, want 3", nf.BlocklistSize())
	}
}

func TestNetFilterAddCIDRInvalid(t *testing.T) {
	nf, err := NewNetFilter(NetFilterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "nope", "10.0.0.0/33", "300.1.1.1"} {
		if err := nf.AddCIDR(bad); err == nil {
			t.Errorf("AddCIDR(%q) should fail", bad)
		}
	}
	if nf.BlocklistSize() != 0 {
		t.Error("invalid entries must not be added")
	}
}

func TestNetFilterIsBlockedUnparseable(t *testing.T) {
	// A catch-all blocklist must still not match garbage input.
	nf, err := NewNetFilter(NetFilterConfig{BlockCIDRs: []string{"0.0.0.0/0", "::/0"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, addr := range []string{"", "example.com", "example.com:80", "not:an:addr", "1.2.3:80"} {
		if nf.IsBlocked(addr) {
			t.Errorf("IsBlocked(%q) = true, want false for unparseable address", addr)
		}
	}
	if !nf.IsBlocked("8.8.8.8") || !nf.IsBlocked("::1") {
		t.Error("catch-all ranges should block valid IPs")
	}
}

func TestNetFilterRemoveCIDR(t *testing.T) {
	nf, err := NewNetFilter(NetFilterConfig{BlockCIDRs: []string{"10.0.0.0/8", "192.168.0.0/16", "1.2.3.4"}})
	if err != nil {
		t.Fatal(err)
	}

	nf.RemoveCIDR("192.168.0.0/16")
	if nf.IsBlocked("192.168.1.1") {
		t.Error("removed CIDR should no longer block")
	}
	if !nf.IsBlocked("10.1.1.1") {
		t.Error("other CIDRs must be unaffected")
	}

	// Single IPs are stored as /32; regression: RemoveCIDR with the same bare
	// IP that was added used to be a no-op.
	nf.RemoveCIDR("1.2.3.4")
	if nf.IsBlocked("1.2.3.4") {
		t.Error("RemoveCIDR(1.2.3.4) should remove the single-IP entry")
	}

	// Removing something not present is a no-op.
	nf.RemoveCIDR("172.16.0.0/12")
	if nf.BlocklistSize() != 1 {
		t.Errorf("BlocklistSize = %d, want 1", nf.BlocklistSize())
	}
}

func TestNetFilterRemoveCIDR_Normalized(t *testing.T) {
	tests := []struct {
		name   string
		add    string
		remove string
		probe  string
	}{
		{"ipv4 bare/bare", "1.2.3.4", "1.2.3.4", "1.2.3.4"},
		{"ipv4 bare/cidr", "1.2.3.4", "1.2.3.4/32", "1.2.3.4"},
		{"ipv4 cidr/bare", "1.2.3.4/32", "1.2.3.4", "1.2.3.4"},
		{"ipv6 bare/bare", "2001:db8::1", "2001:db8::1", "2001:db8::1"},
		{"ipv6 bare/cidr", "2001:db8::1", "2001:db8::1/128", "2001:db8::1"},
		{"ipv6 non-canonical", "2001:0db8:0:0::1", "2001:db8::1", "2001:db8::1"},
		{"cidr host bits", "10.0.0.0/8", "10.1.2.3/8", "10.9.9.9"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			nf, err := NewNetFilter(NetFilterConfig{})
			if err != nil {
				t.Fatal(err)
			}
			if err := nf.AddCIDR(tc.add); err != nil {
				t.Fatalf("AddCIDR(%q): %v", tc.add, err)
			}
			if !nf.IsBlocked(tc.probe) {
				t.Fatalf("precondition: %s should be blocked", tc.probe)
			}
			nf.RemoveCIDR(tc.remove)
			if nf.IsBlocked(tc.probe) || nf.BlocklistSize() != 0 {
				t.Errorf("RemoveCIDR(%q) did not remove %q (size=%d)", tc.remove, tc.add, nf.BlocklistSize())
			}
		})
	}

	// Invalid input is ignored and leaves the blocklist untouched.
	nf, err := NewNetFilter(NetFilterConfig{BlockCIDRs: []string{"1.2.3.4"}})
	if err != nil {
		t.Fatal(err)
	}
	nf.RemoveCIDR("not-an-ip")
	if nf.BlocklistSize() != 1 {
		t.Errorf("BlocklistSize = %d, want 1 after invalid RemoveCIDR", nf.BlocklistSize())
	}
}

func TestNetFilterDefaultWindow(t *testing.T) {
	nf, err := NewNetFilter(NetFilterConfig{RateLimit: 1, Window: -time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if nf.window != time.Minute {
		t.Errorf("window = %v, want default 1m", nf.window)
	}
	if nf.CheckRateLimit(1) {
		t.Error("first connection must pass")
	}
	if !nf.CheckRateLimit(1) {
		t.Error("second connection within default window should be limited")
	}
	if nf.CheckRateLimit(2) {
		t.Error("rate limits are per-PID")
	}
}

func TestNetFilterConcurrentAccess(t *testing.T) {
	nf, err := NewNetFilter(NetFilterConfig{RateLimit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = nf.AddCIDR("10.0.0.0/8")
			_ = nf.IsBlocked("10.0.0.1")
			_ = nf.CheckRateLimit(uint32(i))
			nf.CleanupStale()
			nf.RemoveCIDR("10.0.0.0/8")
			_ = nf.BlocklistSize()
		}()
	}
	wg.Wait()
}
