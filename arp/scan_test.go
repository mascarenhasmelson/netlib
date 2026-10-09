package arp

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

var fastScan = &ScanOptions{Attempts: 2, Delay: time.Microsecond, Wait: 50 * time.Millisecond}

func TestScanFindsHosts(t *testing.T) {
	c, lan := newTestClient(t)
	lan.addHost("192.168.1.1", hostMAC1)
	lan.addHost("192.168.1.50", hostMAC2)
	lan.addHost("192.168.1.254", hostMAC3)
	lan.addHost("10.0.0.1", hostMAC3) // outside the scanned prefix

	results, err := c.Scan(context.Background(), c.LocalPrefix(), fastScan)
	if err != nil {
		t.Fatal(err)
	}

	want := []ScanResult{
		{IP: netip.MustParseAddr("192.168.1.1"), HardwareAddr: hostMAC1},
		{IP: netip.MustParseAddr("192.168.1.50"), HardwareAddr: hostMAC2},
		{IP: netip.MustParseAddr("192.168.1.254"), HardwareAddr: hostMAC3},
	}
	assertResults(t, results, want)

	if d := lan.readDeadline(); !d.IsZero() {
		t.Fatalf("read deadline not cleared: %v", d)
	}
}

func TestScanAddressesRequested(t *testing.T) {
	c, lan := newTestClient(t)

	if _, err := c.Scan(context.Background(), netip.MustParsePrefix("192.168.1.0/24"),
		&ScanOptions{Attempts: 1, Delay: time.Microsecond, Wait: time.Millisecond}); err != nil {
		t.Fatal(err)
	}

	asked := make(map[netip.Addr]int)
	for _, p := range lan.sent() {
		if p.Operation != OperationRequest || p.SenderIP != ourIP || !bytes.Equal(p.SenderHardwareAddr, ourMAC) {
			t.Fatalf("malformed request: %+v", p)
		}
		asked[p.TargetIP]++
	}

	// 254 host addresses minus our own: no network, broadcast or self.
	if len(asked) != 253 {
		t.Fatalf("asked %d addresses, want 253", len(asked))
	}
	for _, skip := range []string{"192.168.1.0", "192.168.1.255", "192.168.1.10"} {
		if asked[netip.MustParseAddr(skip)] != 0 {
			t.Errorf("scan asked %s", skip)
		}
	}
	for ip, n := range asked {
		if n != 1 {
			t.Errorf("asked %s %d times", ip, n)
		}
	}
}

func TestScanRetriesOnlyMissingHosts(t *testing.T) {
	c, lan := newTestClient(t)
	lan.addHost("192.168.1.1", hostMAC1)
	lan.addHost("192.168.1.2", hostMAC2)
	lan.dropRequests("192.168.1.2", 1) // first request to .2 is lost

	results, err := c.Scan(context.Background(), netip.MustParsePrefix("192.168.1.0/29"), fastScan)
	if err != nil {
		t.Fatal(err)
	}
	assertResults(t, results, []ScanResult{
		{IP: netip.MustParseAddr("192.168.1.1"), HardwareAddr: hostMAC1},
		{IP: netip.MustParseAddr("192.168.1.2"), HardwareAddr: hostMAC2},
	})

	asked := make(map[netip.Addr]int)
	for _, p := range lan.sent() {
		asked[p.TargetIP]++
	}
	if n := asked[netip.MustParseAddr("192.168.1.1")]; n != 1 {
		t.Errorf("answered host .1 asked %d times, want 1", n)
	}
	if n := asked[netip.MustParseAddr("192.168.1.2")]; n != 2 {
		t.Errorf("host .2 asked %d times, want 2", n)
	}
	if n := asked[netip.MustParseAddr("192.168.1.3")]; n != 2 {
		t.Errorf("silent host .3 asked %d times, want 2", n)
	}
}

func TestScanDetectsDuplicateIP(t *testing.T) {
	c, lan := newTestClient(t)
	lan.addHost("192.168.1.5", hostMAC1)
	lan.addHost("192.168.1.5", hostMAC2) // two devices claim .5

	results, err := c.Scan(context.Background(), netip.MustParsePrefix("192.168.1.0/29"), fastScan)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	r := results[0]
	if !bytes.Equal(r.HardwareAddr, hostMAC1) || len(r.Duplicates) != 1 || !bytes.Equal(r.Duplicates[0], hostMAC2) {
		t.Fatalf("conflict not reported: %+v", r)
	}
}

func TestScanOnResult(t *testing.T) {
	c, lan := newTestClient(t)
	lan.addHost("192.168.1.1", hostMAC1)
	lan.addHost("192.168.1.2", hostMAC2)

	var (
		mu   sync.Mutex
		seen []netip.Addr
	)
	opts := *fastScan
	opts.OnResult = func(r ScanResult) {
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, r.IP)
	}

	if _, err := c.Scan(context.Background(), netip.MustParsePrefix("192.168.1.0/29"), &opts); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 {
		t.Fatalf("OnResult called for %v, want 2 hosts once each", seen)
	}
}

func TestScanSmallPrefixes(t *testing.T) {
	tests := []struct {
		prefix string
		first  string
		count  uint64
	}{
		{"192.168.1.0/24", "192.168.1.1", 254},
		{"192.168.1.77/24", "192.168.1.1", 254}, // host bits are masked
		{"10.0.0.0/16", "10.0.0.1", 65534},
		{"192.168.1.4/30", "192.168.1.5", 2},
		{"192.168.1.4/31", "192.168.1.4", 2}, // point-to-point: both usable
		{"192.168.1.9/32", "192.168.1.9", 1},
		{"0.0.0.0/0", "0.0.0.1", 1<<32 - 2},
	}
	for _, tt := range tests {
		first, count := hostRange(netip.MustParsePrefix(tt.prefix))
		if first != netip.MustParseAddr(tt.first) || count != tt.count {
			t.Errorf("hostRange(%s) = %s, %d; want %s, %d", tt.prefix, first, count, tt.first, tt.count)
		}
	}
}

func TestScanSingleHostPrefix(t *testing.T) {
	c, lan := newTestClient(t)
	lan.addHost("192.168.1.1", hostMAC1)

	results, err := c.Scan(context.Background(), netip.MustParsePrefix("192.168.1.1/32"), fastScan)
	if err != nil {
		t.Fatal(err)
	}
	assertResults(t, results, []ScanResult{{IP: netip.MustParseAddr("192.168.1.1"), HardwareAddr: hostMAC1}})
}

func TestScanPrefixTooLarge(t *testing.T) {
	c, lan := newTestClient(t)

	_, err := c.Scan(context.Background(), netip.MustParsePrefix("10.0.0.0/8"), nil)
	if !errors.Is(err, ErrPrefixTooLarge) {
		t.Fatalf("got %v, want ErrPrefixTooLarge", err)
	}
	if n := len(lan.sent()); n != 0 {
		t.Fatalf("sent %d requests before refusing", n)
	}

	_, err = c.Scan(context.Background(), netip.MustParsePrefix("192.168.1.0/24"), &ScanOptions{MaxHosts: 100})
	if !errors.Is(err, ErrPrefixTooLarge) {
		t.Fatalf("custom limit: got %v, want ErrPrefixTooLarge", err)
	}
}

func TestScanInvalidPrefix(t *testing.T) {
	c, _ := newTestClient(t)

	for _, p := range []netip.Prefix{{}, netip.MustParsePrefix("fe80::/64")} {
		if _, err := c.Scan(context.Background(), p, nil); !errors.Is(err, ErrInvalidIP) {
			t.Errorf("Scan(%q): got %v, want ErrInvalidIP", p, err)
		}
	}
	if _, err := (&Client{}).Scan(context.Background(), netip.MustParsePrefix("192.168.1.0/24"), nil); err != errNoIPv4Addr {
		t.Errorf("no address: got %v", err)
	}
}

func TestScanCanceledReturnsPartialResults(t *testing.T) {
	c, lan := newTestClient(t)
	lan.addHost("192.168.1.1", hostMAC1)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// A slow scan that would take 2.5s for the /24.
	start := time.Now()
	results, err := c.Scan(ctx, c.LocalPrefix(), &ScanOptions{Delay: 10 * time.Millisecond})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v, want context.DeadlineExceeded", err)
	}
	if took := time.Since(start); took > time.Second {
		t.Fatalf("scan ignored cancel, took %v", took)
	}
	assertResults(t, results, []ScanResult{{IP: netip.MustParseAddr("192.168.1.1"), HardwareAddr: hostMAC1}})
}

func TestScanReadError(t *testing.T) {
	errRead := errors.New("read failed")
	c := &Client{
		ifi: &net.Interface{HardwareAddr: ourMAC},
		ip:  ourIP,
		p:   &errReadFromPacketConn{err: errRead},
	}

	_, err := c.Scan(context.Background(), netip.MustParsePrefix("192.168.1.0/24"), fastScan)
	if !errors.Is(err, errRead) {
		t.Fatalf("got %v, want %v", err, errRead)
	}
}

func assertResults(t *testing.T, got, want []ScanResult) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d results %v, want %d %v", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i].IP != want[i].IP || !bytes.Equal(got[i].HardwareAddr, want[i].HardwareAddr) ||
			len(got[i].Duplicates) != len(want[i].Duplicates) {
			t.Fatalf("result %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}
