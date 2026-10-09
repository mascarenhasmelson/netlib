package arp

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

var fastProbe = &ProbeOptions{
	Count:       3,
	MinInterval: 10 * time.Millisecond,
	MaxInterval: 20 * time.Millisecond,
	Wait:        50 * time.Millisecond,
}

func TestProbeAddressFree(t *testing.T) {
	c, lan := newTestClient(t)
	lan.addHost("192.168.1.1", hostMAC1) // a different address

	target := netip.MustParseAddr("192.168.1.20")
	if err := c.Probe(context.Background(), target, fastProbe); err != nil {
		t.Fatalf("free address reported as: %v", err)
	}

	sent := lan.sent()
	if len(sent) != 3 {
		t.Fatalf("sent %d probes, want 3", len(sent))
	}
	zero := make(net.HardwareAddr, 6)
	for i, p := range sent {
		// RFC 5227 probe: request, sender IP 0.0.0.0, target MAC zero.
		if p.Operation != OperationRequest || !p.SenderIP.IsUnspecified() || p.TargetIP != target ||
			!bytes.Equal(p.SenderHardwareAddr, ourMAC) || !bytes.Equal(p.TargetHardwareAddr, zero) {
			t.Fatalf("probe %d malformed: %+v", i, p)
		}
	}

	times := lan.sentTimes()
	for i := 1; i < len(times); i++ {
		if gap := times[i].Sub(times[i-1]); gap < 9*time.Millisecond {
			t.Errorf("probe %d sent %v after the previous one, want 10-20ms", i, gap)
		}
	}
	if d := lan.readDeadline(); !d.IsZero() {
		t.Fatalf("read deadline not cleared: %v", d)
	}
}

func TestProbeAddressInUse(t *testing.T) {
	c, lan := newTestClient(t)
	lan.addHost("192.168.1.20", hostMAC2)

	err := c.Probe(context.Background(), netip.MustParseAddr("192.168.1.20"), fastProbe)
	if !errors.Is(err, ErrAddressInUse) {
		t.Fatalf("got %v, want ErrAddressInUse", err)
	}

	var conflict *ConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("error %T is not a *ConflictError", err)
	}
	if conflict.IP != netip.MustParseAddr("192.168.1.20") || !bytes.Equal(conflict.HardwareAddr, hostMAC2) {
		t.Fatalf("unexpected conflict: %+v", conflict)
	}
	if !strings.Contains(err.Error(), "192.168.1.20") || !strings.Contains(err.Error(), hostMAC2.String()) {
		t.Fatalf("error message lacks details: %v", err)
	}
	if n := len(lan.sent()); n != 1 {
		t.Fatalf("kept probing after conflict: sent %d", n)
	}
}

func TestProbeSimultaneousProbe(t *testing.T) {
	// Another device probing for the same address is also a conflict.
	c, lan := newTestClient(t)
	lan.inject(mustPacket(t, OperationRequest, hostMAC3, "0.0.0.0", make(net.HardwareAddr, 6), "192.168.1.20"),
		net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})

	var conflict *ConflictError
	err := c.Probe(context.Background(), netip.MustParseAddr("192.168.1.20"), fastProbe)
	if !errors.As(err, &conflict) || !bytes.Equal(conflict.HardwareAddr, hostMAC3) {
		t.Fatalf("got %v, want conflict with %s", err, hostMAC3)
	}
}

func TestProbeConflictFromAnnouncement(t *testing.T) {
	// Any packet whose sender IP is the probed address is a conflict, such
	// as another device's gratuitous ARP.
	c, lan := newTestClient(t)
	lan.inject(mustPacket(t, OperationRequest, hostMAC1, "192.168.1.20", make(net.HardwareAddr, 6), "192.168.1.20"),
		net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})

	if err := c.Probe(context.Background(), netip.MustParseAddr("192.168.1.20"), fastProbe); !errors.Is(err, ErrAddressInUse) {
		t.Fatalf("got %v, want ErrAddressInUse", err)
	}
}

func TestProbeIgnoresUnrelatedTraffic(t *testing.T) {
	c, lan := newTestClient(t)
	// Requests and replies about other addresses, and a probe for another
	// address, must not count as conflicts.
	lan.inject(mustPacket(t, OperationReply, hostMAC1, "192.168.1.1", ourMAC, "192.168.1.10"), ourMAC)
	lan.inject(mustPacket(t, OperationRequest, hostMAC2, "192.168.1.2", make(net.HardwareAddr, 6), "192.168.1.20"),
		net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	lan.inject(mustPacket(t, OperationRequest, hostMAC3, "0.0.0.0", make(net.HardwareAddr, 6), "192.168.1.21"),
		net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})

	if err := c.Probe(context.Background(), netip.MustParseAddr("192.168.1.20"), fastProbe); err != nil {
		t.Fatalf("unrelated traffic caused: %v", err)
	}
}

func TestProbeCanceled(t *testing.T) {
	c, _ := newTestClient(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := c.Probe(ctx, netip.MustParseAddr("192.168.1.20"), nil) // defaults take ~5s
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v, want context.DeadlineExceeded", err)
	}
	if took := time.Since(start); took > time.Second {
		t.Fatalf("cancel took %v", took)
	}
}

func TestProbeInitialWait(t *testing.T) {
	c, lan := newTestClient(t)

	opts := *fastProbe
	opts.Count = 1
	opts.InitialWait = 40 * time.Millisecond

	start := time.Now()
	if err := c.Probe(context.Background(), netip.MustParseAddr("192.168.1.20"), &opts); err != nil {
		t.Fatal(err)
	}
	// The single probe was sent at a random point within InitialWait.
	if sent := lan.sentTimes(); len(sent) != 1 || sent[0].Sub(start) > 200*time.Millisecond {
		t.Fatalf("unexpected probe timing: %v", sent)
	}
}

func TestProbeInvalidInput(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := context.Background()

	for _, ip := range []netip.Addr{{}, netip.IPv4Unspecified(), ipv6loopback()} {
		if err := c.Probe(ctx, ip, fastProbe); err != ErrInvalidIP {
			t.Errorf("Probe(%v): got %v, want ErrInvalidIP", ip, err)
		}
	}
	if err := (&Client{}).Probe(ctx, ourIP, fastProbe); err != ErrInvalidHardwareAddr {
		t.Errorf("no interface: got %v, want ErrInvalidHardwareAddr", err)
	}
}

func TestAnnounce(t *testing.T) {
	c, lan := newTestClient(t)

	ip := netip.MustParseAddr("192.168.1.10")
	if err := c.Announce(context.Background(), ip, &AnnounceOptions{Count: 2, Interval: 30 * time.Millisecond}); err != nil {
		t.Fatal(err)
	}

	sent := lan.sent()
	if len(sent) != 2 {
		t.Fatalf("sent %d announcements, want 2", len(sent))
	}
	zero := make(net.HardwareAddr, 6)
	for i, p := range sent {
		// RFC 5227 announcement: request with sender IP == target IP.
		if p.Operation != OperationRequest || p.SenderIP != ip || p.TargetIP != ip ||
			!bytes.Equal(p.SenderHardwareAddr, ourMAC) || !bytes.Equal(p.TargetHardwareAddr, zero) {
			t.Fatalf("announcement %d malformed: %+v", i, p)
		}
	}
	times := lan.sentTimes()
	if gap := times[1].Sub(times[0]); gap < 25*time.Millisecond {
		t.Fatalf("announcements %v apart, want 30ms", gap)
	}
}

func TestAnnounceDefaultsAndCancel(t *testing.T) {
	c, lan := newTestClient(t)

	// The default interval is 2s, so canceling after the first packet
	// must return quickly with exactly one announcement sent.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	if err := c.Announce(ctx, ourIP, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v, want context.DeadlineExceeded", err)
	}
	if n := len(lan.sent()); n != 1 {
		t.Fatalf("sent %d announcements, want 1", n)
	}
}

func TestAnnounceInvalidInput(t *testing.T) {
	c, _ := newTestClient(t)
	ctx := context.Background()

	if err := c.Announce(ctx, netip.IPv4Unspecified(), nil); err != ErrInvalidIP {
		t.Errorf("0.0.0.0: got %v", err)
	}
	if err := c.Announce(ctx, ipv6loopback(), nil); err != ErrInvalidIP {
		t.Errorf("IPv6: got %v", err)
	}
	if err := (&Client{}).Announce(ctx, ourIP, nil); err != ErrInvalidHardwareAddr {
		t.Errorf("no interface: got %v", err)
	}
}

func TestProbeThenAnnounce(t *testing.T) {
	// The typical RFC 5227 flow: probe, and claim the address if free.
	c, lan := newTestClient(t)
	ip := netip.MustParseAddr("192.168.1.30")

	if err := c.Probe(context.Background(), ip, fastProbe); err != nil {
		t.Fatal(err)
	}
	if err := c.Announce(context.Background(), ip, &AnnounceOptions{Count: 1}); err != nil {
		t.Fatal(err)
	}
	if n := len(lan.sent()); n != 4 {
		t.Fatalf("sent %d packets, want 3 probes + 1 announcement", n)
	}
}

func TestRandDuration(t *testing.T) {
	for range 1000 {
		d := randDuration(10*time.Millisecond, 20*time.Millisecond)
		if d < 10*time.Millisecond || d > 20*time.Millisecond {
			t.Fatalf("randDuration out of range: %v", d)
		}
	}
	if d := randDuration(5, 5); d != 5 {
		t.Fatalf("randDuration(5, 5) = %v", d)
	}
}
