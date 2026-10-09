package arp

import (
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/mascarenhasmelson/netlib/ethernet"
)

// fakeLAN is a net.PacketConn that simulates an Ethernet segment. Hosts
// registered with addHost answer ARP requests for their address. Like a Linux
// packet socket, it also delivers the frames the Client writes back to it.
// Read deadlines behave like those of a real socket.
type fakeLAN struct {
	t *testing.T

	mu        sync.Mutex
	hosts     map[netip.Addr][]net.HardwareAddr
	drop      map[netip.Addr]int
	written   []*Packet
	writeTime []time.Time
	deadline  time.Time
	changed   chan struct{} // closed and replaced when the deadline changes
	noEcho    bool

	in     chan []byte
	closed chan struct{}
	once   sync.Once
}

func newFakeLAN(t *testing.T) *fakeLAN {
	t.Helper()
	return &fakeLAN{
		t:       t,
		hosts:   make(map[netip.Addr][]net.HardwareAddr),
		drop:    make(map[netip.Addr]int),
		changed: make(chan struct{}),
		in:      make(chan []byte, 4096),
		closed:  make(chan struct{}),
	}
}

// addHost registers a device that answers ARP requests for ip. Registering
// two hardware addresses for one ip simulates an address conflict.
func (l *fakeLAN) addHost(ip string, mac net.HardwareAddr) {
	l.mu.Lock()
	defer l.mu.Unlock()
	a := netip.MustParseAddr(ip)
	l.hosts[a] = append(l.hosts[a], mac)
}

// dropRequests makes the hosts at ip ignore the next n requests.
func (l *fakeLAN) dropRequests(ip string, n int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.drop[netip.MustParseAddr(ip)] = n
}

// sent returns the ARP packets written so far.
func (l *fakeLAN) sent() []*Packet {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]*Packet(nil), l.written...)
}

func (l *fakeLAN) sentTimes() []time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]time.Time(nil), l.writeTime...)
}

// inject delivers an ARP packet from another device to the Client.
func (l *fakeLAN) inject(p *Packet, dst net.HardwareAddr) {
	l.t.Helper()
	l.deliver(mustFrame(l.t, p, dst))
}

func (l *fakeLAN) deliver(b []byte) {
	select {
	case l.in <- b:
	default:
		l.t.Error("fakeLAN: receive queue full")
	}
}

func (l *fakeLAN) WriteTo(b []byte, _ net.Addr) (int, error) {
	select {
	case <-l.closed:
		return 0, net.ErrClosed
	default:
	}

	p, _, err := parsePacket(b)
	if err != nil {
		l.t.Errorf("fakeLAN: client wrote an invalid ARP frame: %v", err)
		return 0, err
	}

	l.mu.Lock()
	l.written = append(l.written, p)
	l.writeTime = append(l.writeTime, time.Now())
	echo := !l.noEcho

	var replies [][]byte
	if p.Operation == OperationRequest {
		if l.drop[p.TargetIP] > 0 {
			l.drop[p.TargetIP]--
		} else {
			for _, mac := range l.hosts[p.TargetIP] {
				reply, err := NewPacket(OperationReply, mac, p.TargetIP, p.SenderHardwareAddr, p.SenderIP)
				if err != nil {
					l.mu.Unlock()
					l.t.Errorf("fakeLAN: building reply: %v", err)
					return 0, err
				}
				replies = append(replies, mustFrame(l.t, reply, p.SenderHardwareAddr))
			}
		}
	}
	l.mu.Unlock()

	if echo {
		l.deliver(append([]byte(nil), b...))
	}
	for _, r := range replies {
		l.deliver(r)
	}
	return len(b), nil
}

func (l *fakeLAN) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		l.mu.Lock()
		deadline, changed := l.deadline, l.changed
		l.mu.Unlock()

		var (
			timer   *time.Timer
			timeout <-chan time.Time
		)
		if !deadline.IsZero() {
			d := time.Until(deadline)
			if d <= 0 {
				return 0, nil, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(d)
			timeout = timer.C
		}

		n, err, retry := 0, error(nil), false
		select {
		case frame := <-l.in:
			n = copy(b, frame)
		case <-timeout:
			err = os.ErrDeadlineExceeded
		case <-changed:
			retry = true // deadline changed: re-evaluate it
		case <-l.closed:
			err = net.ErrClosed
		}
		if timer != nil {
			timer.Stop()
		}
		if !retry {
			return n, nil, err
		}
	}
}

func (l *fakeLAN) SetReadDeadline(t time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.deadline = t
	close(l.changed)
	l.changed = make(chan struct{})
	return nil
}

func (l *fakeLAN) SetDeadline(t time.Time) error      { return l.SetReadDeadline(t) }
func (l *fakeLAN) SetWriteDeadline(t time.Time) error { return nil }
func (l *fakeLAN) LocalAddr() net.Addr                { return nil }

func (l *fakeLAN) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

// readDeadline returns the current read deadline.
func (l *fakeLAN) readDeadline() time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.deadline
}

var (
	ourMAC   = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	ourIP    = netip.MustParseAddr("192.168.1.10")
	hostMAC1 = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0xa1}
	hostMAC2 = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0xa2}
	hostMAC3 = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0xa3}
)

// newTestClient returns a Client at 192.168.1.10/24 on a fresh fakeLAN.
func newTestClient(t *testing.T) (*Client, *fakeLAN) {
	t.Helper()
	lan := newFakeLAN(t)
	ifi := &net.Interface{Name: "fake0", HardwareAddr: ourMAC, MTU: 1500}
	c, err := newClientAddrs(ifi, lan, []net.Addr{
		&net.IPNet{IP: net.ParseIP("192.168.1.10").To4(), Mask: net.CIDRMask(24, 32)},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c, lan
}

func mustFrame(t *testing.T, p *Packet, dst net.HardwareAddr) []byte {
	t.Helper()
	pb, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	b, err := (&ethernet.Frame{
		Destination: dst,
		Source:      p.SenderHardwareAddr,
		EtherType:   ethernet.EtherTypeARP,
		Payload:     pb,
	}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustPacket(t *testing.T, op Operation, srcHW net.HardwareAddr, srcIP string, dstHW net.HardwareAddr, dstIP string) *Packet {
	t.Helper()
	p, err := NewPacket(op, srcHW, netip.MustParseAddr(srcIP), dstHW, netip.MustParseAddr(dstIP))
	if err != nil {
		t.Fatal(err)
	}
	return p
}
