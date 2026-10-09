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

var fastResolve = &ResolveOptions{Attempts: 3, Interval: 50 * time.Millisecond}

func TestResolveContextOK(t *testing.T) {
	c, lan := newTestClient(t)
	lan.addHost("192.168.1.1", hostMAC1)

	mac, err := c.ResolveContext(context.Background(), netip.MustParseAddr("192.168.1.1"), fastResolve)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mac, hostMAC1) {
		t.Fatalf("unexpected MAC: %s, want %s", mac, hostMAC1)
	}
	if n := len(lan.sent()); n != 1 {
		t.Fatalf("sent %d requests, want 1", n)
	}
	if d := lan.readDeadline(); !d.IsZero() {
		t.Fatalf("read deadline not cleared: %v", d)
	}
}

func TestResolveContextRetriesAfterLostRequests(t *testing.T) {
	c, lan := newTestClient(t)
	lan.addHost("192.168.1.1", hostMAC1)
	lan.dropRequests("192.168.1.1", 2) // first two requests are lost

	mac, err := c.ResolveContext(context.Background(), netip.MustParseAddr("192.168.1.1"), fastResolve)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mac, hostMAC1) {
		t.Fatalf("unexpected MAC: %s", mac)
	}

	sent := lan.sent()
	if len(sent) != 3 {
		t.Fatalf("sent %d requests, want 3", len(sent))
	}
	for i, p := range sent {
		if p.Operation != OperationRequest || p.TargetIP != netip.MustParseAddr("192.168.1.1") ||
			p.SenderIP != ourIP || !bytes.Equal(p.SenderHardwareAddr, ourMAC) {
			t.Fatalf("request %d malformed: %+v", i, p)
		}
	}

	// Requests are spaced by the interval.
	times := lan.sentTimes()
	if gap := times[1].Sub(times[0]); gap < 40*time.Millisecond {
		t.Fatalf("retry sent after %v, want about 50ms", gap)
	}
}

func TestResolveContextNoResponse(t *testing.T) {
	c, lan := newTestClient(t)

	start := time.Now()
	_, err := c.ResolveContext(context.Background(), netip.MustParseAddr("192.168.1.99"), fastResolve)
	if !errors.Is(err, ErrNoResponse) {
		t.Fatalf("got %v, want ErrNoResponse", err)
	}
	if !strings.Contains(err.Error(), "192.168.1.99") || !strings.Contains(err.Error(), "3 attempts") {
		t.Fatalf("error lacks details: %v", err)
	}
	if n := len(lan.sent()); n != 3 {
		t.Fatalf("sent %d requests, want 3", n)
	}
	if took := time.Since(start); took < 140*time.Millisecond || took > 2*time.Second {
		t.Fatalf("took %v, want about 150ms", took)
	}
}

func TestResolveContextDefaults(t *testing.T) {
	c, lan := newTestClient(t)
	lan.addHost("192.168.1.1", hostMAC1)

	mac, err := c.ResolveContext(context.Background(), netip.MustParseAddr("192.168.1.1"), nil)
	if err != nil || !bytes.Equal(mac, hostMAC1) {
		t.Fatalf("got %s, %v", mac, err)
	}
}

func TestResolveContextCanceled(t *testing.T) {
	c, _ := newTestClient(t)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(30 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	_, err := c.ResolveContext(ctx, netip.MustParseAddr("192.168.1.99"),
		&ResolveOptions{Attempts: 10, Interval: time.Second})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context.Canceled", err)
	}
	if took := time.Since(start); took > 500*time.Millisecond {
		t.Fatalf("cancel took %v", took)
	}
}

func TestResolveContextDeadline(t *testing.T) {
	c, _ := newTestClient(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()

	_, err := c.ResolveContext(ctx, netip.MustParseAddr("192.168.1.99"),
		&ResolveOptions{Attempts: 10, Interval: time.Second})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v, want context.DeadlineExceeded", err)
	}
}

func TestResolveContextAlreadyCanceled(t *testing.T) {
	c, lan := newTestClient(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.ResolveContext(ctx, netip.MustParseAddr("192.168.1.1"), nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	if n := len(lan.sent()); n != 0 {
		t.Fatalf("sent %d requests after cancel", n)
	}
}

func TestResolveContextInvalidInput(t *testing.T) {
	c, _ := newTestClient(t)

	if _, err := c.ResolveContext(context.Background(), ipv6loopback(), nil); err != ErrInvalidIP {
		t.Fatalf("IPv6 target: got %v, want ErrInvalidIP", err)
	}
	if _, err := (&Client{}).ResolveContext(context.Background(), ourIP, nil); err != errNoIPv4Addr {
		t.Fatalf("no address: got %v, want errNoIPv4Addr", err)
	}
}

func TestResolveContextReadError(t *testing.T) {
	errRead := errors.New("read failed")
	c := &Client{
		ifi: &net.Interface{HardwareAddr: ourMAC},
		ip:  ourIP,
		p:   &errReadFromPacketConn{err: errRead},
	}

	_, err := c.ResolveContext(context.Background(), netip.MustParseAddr("192.168.1.1"), fastResolve)
	if !errors.Is(err, errRead) {
		t.Fatalf("got %v, want %v", err, errRead)
	}
}

func TestResolveContextIgnoresOtherTraffic(t *testing.T) {
	c, lan := newTestClient(t)
	lan.addHost("192.168.1.1", hostMAC1)

	// Unrelated replies and requests arrive before the real answer.
	lan.inject(mustPacket(t, OperationReply, hostMAC2, "192.168.1.2", ourMAC, "192.168.1.10"), ourMAC)
	lan.inject(mustPacket(t, OperationRequest, hostMAC3, "192.168.1.3", make(net.HardwareAddr, 6), "192.168.1.1"), ourMAC)

	mac, err := c.ResolveContext(context.Background(), netip.MustParseAddr("192.168.1.1"), fastResolve)
	if err != nil || !bytes.Equal(mac, hostMAC1) {
		t.Fatalf("got %s, %v; want %s", mac, err, hostMAC1)
	}
}

func TestResolveStillWorks(t *testing.T) {
	// The original blocking Resolve keeps working alongside ResolveContext.
	c, lan := newTestClient(t)
	lan.addHost("192.168.1.1", hostMAC1)

	if err := c.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	mac, err := c.Resolve(netip.MustParseAddr("192.168.1.1"))
	if err != nil || !bytes.Equal(mac, hostMAC1) {
		t.Fatalf("got %s, %v", mac, err)
	}
}

func TestClientReadLargeFrame(t *testing.T) {
	// A 64 byte hardware address makes a 158 byte frame, which the old
	// fixed 128 byte buffer truncated.
	c, lan := newTestClient(t)

	big := bytes.Repeat([]byte{0xab}, 64)
	p := &Packet{
		HardwareType:       1,
		ProtocolType:       0x0800,
		HardwareAddrLength: 64,
		IPLength:           4,
		Operation:          OperationReply,
		SenderHardwareAddr: big,
		SenderIP:           netip.MustParseAddr("192.168.1.1"),
		TargetHardwareAddr: big,
		TargetIP:           ourIP,
	}
	pb, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	frame := append([]byte{
		0x02, 0, 0, 0, 0, 0x01,
		0x02, 0, 0, 0, 0, 0xa1,
		0x08, 0x06,
	}, pb...)
	if len(frame) <= minReadBufferSize {
		t.Fatalf("test frame is only %d bytes", len(frame))
	}
	lan.deliver(frame)

	got, _, err := c.Read()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.SenderHardwareAddr, big) || got.TargetIP != ourIP {
		t.Fatalf("frame decoded incorrectly: %+v", got)
	}
}

func TestClientReadBufferSize(t *testing.T) {
	tests := []struct {
		ifi  *net.Interface
		want int
	}{
		{ifi: nil, want: 128},
		{ifi: &net.Interface{MTU: 0}, want: 128},
		{ifi: &net.Interface{MTU: 1500}, want: 1522},
		{ifi: &net.Interface{MTU: 9000}, want: 9022},
	}
	for _, tt := range tests {
		c := &Client{ifi: tt.ifi}
		if got := c.readBufferSize(); got != tt.want {
			t.Errorf("readBufferSize(%v) = %d, want %d", tt.ifi, got, tt.want)
		}
	}
}

func TestNewClientAddrsPrefix(t *testing.T) {
	ifi := &net.Interface{HardwareAddr: ourMAC}
	c, err := newClientAddrs(ifi, nil, []net.Addr{
		&net.IPNet{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)},
		&net.IPNet{IP: net.ParseIP("10.20.30.40").To4(), Mask: net.CIDRMask(20, 32)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := netip.MustParseAddr("10.20.30.40"); c.IP() != want {
		t.Errorf("IP() = %s, want %s", c.IP(), want)
	}
	if want := netip.MustParsePrefix("10.20.16.0/20"); c.LocalPrefix() != want {
		t.Errorf("LocalPrefix() = %s, want %s", c.LocalPrefix(), want)
	}
}
