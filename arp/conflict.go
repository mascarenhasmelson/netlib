package arp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"time"

	"github.com/mascarenhasmelson/netlib/ethernet"
)

// Timing constants from RFC 5227, section 1.1.
const (
	ProbeWait        = 1 * time.Second // maximum initial random delay
	ProbeNum         = 3               // number of probe packets
	ProbeMin         = 1 * time.Second // minimum delay until repeated probe
	ProbeMax         = 2 * time.Second // maximum delay until repeated probe
	AnnounceWait     = 2 * time.Second // delay before announcing
	AnnounceNum      = 2               // number of announcement packets
	AnnounceInterval = 2 * time.Second // time between announcement packets
)

// ErrAddressInUse matches the error returned by Probe when another device
// already uses the probed address. Use errors.As with *ConflictError to learn
// which device.
var ErrAddressInUse = errors.New("arp: address already in use")

// A ConflictError reports that another device uses, or is also probing for,
// an IPv4 address.
type ConflictError struct {
	// IP is the address in conflict.
	IP netip.Addr

	// HardwareAddr is the hardware address of the other device.
	HardwareAddr net.HardwareAddr
}

func (e *ConflictError) Error() string {
	return fmt.Sprintf("arp: address %s already in use by %s", e.IP, e.HardwareAddr)
}

// Is makes errors.Is(err, ErrAddressInUse) report true for a *ConflictError.
func (e *ConflictError) Is(target error) bool { return target == ErrAddressInUse }

// ProbeOptions configures Probe. A nil *ProbeOptions or a zero field uses the
// RFC 5227 defaults, except InitialWait.
type ProbeOptions struct {
	// Count is the number of probes to send. Zero means ProbeNum.
	Count int

	// MinInterval and MaxInterval bound the random delay between probes.
	// Zero means ProbeMin and ProbeMax.
	MinInterval, MaxInterval time.Duration

	// Wait is how long to listen for conflicts after the last probe.
	// Zero means AnnounceWait.
	Wait time.Duration

	// InitialWait is the maximum random delay before the first probe, which
	// avoids many hosts probing at once after a power failure. Zero means no
	// delay; set it to ProbeWait for strict RFC 5227 behavior.
	InitialWait time.Duration
}

// Probe checks whether ip is free to use, following RFC 5227 (IPv4 Address
// Conflict Detection). It broadcasts ARP probes, which use the sender address
// 0.0.0.0 so they do not disturb other hosts' ARP caches, and listens for any
// device that answers for ip or is probing for it at the same time.
//
// Probe returns nil if ip appears to be free, a *ConflictError matching
// ErrAddressInUse if another device uses it, or ctx.Err() if ctx ends first.
// With default options a probe takes about 4 to 6 seconds.
//
// Probe manages the read deadline of the Client while it runs and clears it
// before returning. It must not be used concurrently with Read or with other
// methods that read, such as ResolveContext and Scan.
func (c *Client) Probe(ctx context.Context, ip netip.Addr, opts *ProbeOptions) error {
	o := ProbeOptions{
		Count:       ProbeNum,
		MinInterval: ProbeMin,
		MaxInterval: ProbeMax,
		Wait:        AnnounceWait,
	}
	if opts != nil {
		if opts.Count > 0 {
			o.Count = opts.Count
		}
		if opts.MinInterval > 0 {
			o.MinInterval = opts.MinInterval
		}
		if opts.MaxInterval > 0 {
			o.MaxInterval = opts.MaxInterval
		}
		if opts.Wait > 0 {
			o.Wait = opts.Wait
		}
		o.InitialWait = opts.InitialWait
	}
	o.MaxInterval = max(o.MaxInterval, o.MinInterval)

	if !ip.Is4() || ip.IsUnspecified() {
		return ErrInvalidIP
	}
	mac := c.hwAddr()
	if len(mac) < 6 {
		return ErrInvalidHardwareAddr
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	conflicts := make(chan *ConflictError, 1)
	r := c.startReader(func(p *Packet, _ *ethernet.Frame) {
		if bytes.Equal(p.SenderHardwareAddr, mac) {
			return // our own packet
		}

		// RFC 5227, section 2.1.1: a conflict is any ARP packet whose sender
		// IP is ip, or a probe from another device whose target IP is ip.
		inUse := p.SenderIP == ip
		probing := p.Operation == OperationRequest && p.SenderIP.IsUnspecified() && p.TargetIP == ip
		if !inUse && !probing {
			return
		}

		select {
		case conflicts <- &ConflictError{IP: ip, HardwareAddr: p.SenderHardwareAddr}:
		default:
		}
	})
	defer r.stop()

	timer := time.NewTimer(0)
	defer timer.Stop()
	<-timer.C

	wait := func(d time.Duration) error {
		timer.Reset(d)
		select {
		case conflict := <-conflicts:
			return conflict
		case <-ctx.Done():
			return ctx.Err()
		case <-r.done:
			if err := r.stop(); err != nil {
				return err
			}
			return errReaderStopped
		case <-timer.C:
			return nil
		}
	}

	if o.InitialWait > 0 {
		if err := wait(randDuration(0, o.InitialWait)); err != nil {
			return err
		}
	}

	probe, err := NewPacket(OperationRequest, mac, netip.IPv4Unspecified(),
		make(net.HardwareAddr, len(mac)), ip)
	if err != nil {
		return err
	}

	for i := range o.Count {
		if err := c.WriteTo(probe, ethernet.Broadcast); err != nil {
			return err
		}

		d := o.Wait
		if i < o.Count-1 {
			d = randDuration(o.MinInterval, o.MaxInterval)
		}
		if err := wait(d); err != nil {
			return err
		}
	}

	return nil
}

// AnnounceOptions configures Announce. A nil *AnnounceOptions or a zero field
// uses the RFC 5227 defaults.
type AnnounceOptions struct {
	// Count is the number of announcements to send. Zero means AnnounceNum.
	Count int

	// Interval is the delay between announcements.
	// Zero means AnnounceInterval.
	Interval time.Duration
}

// Announce broadcasts gratuitous ARP announcements, as defined in RFC 5227,
// telling every device on the network that ip now belongs to this Client's
// hardware address. Devices update their ARP caches straight away.
//
// Use it after Probe succeeds, after changing an interface's address, or to
// move an address to this machine during failover. Announcing an address that
// another device uses redirects that device's traffic here, so only announce
// addresses you own.
func (c *Client) Announce(ctx context.Context, ip netip.Addr, opts *AnnounceOptions) error {
	count, interval := AnnounceNum, AnnounceInterval
	if opts != nil {
		if opts.Count > 0 {
			count = opts.Count
		}
		if opts.Interval > 0 {
			interval = opts.Interval
		}
	}

	if !ip.Is4() || ip.IsUnspecified() {
		return ErrInvalidIP
	}
	mac := c.hwAddr()
	if len(mac) < 6 {
		return ErrInvalidHardwareAddr
	}

	// An announcement is a request whose sender and target IP are both ip.
	p, err := NewPacket(OperationRequest, mac, ip, make(net.HardwareAddr, len(mac)), ip)
	if err != nil {
		return err
	}

	timer := time.NewTimer(0)
	defer timer.Stop()
	<-timer.C

	for i := range count {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := c.WriteTo(p, ethernet.Broadcast); err != nil {
			return err
		}

		if i == count-1 {
			break
		}
		timer.Reset(interval)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}

	return nil
}

// hwAddr returns the interface hardware address, or nil if there is none.
func (c *Client) hwAddr() net.HardwareAddr {
	if c.ifi == nil {
		return nil
	}
	return c.ifi.HardwareAddr
}

// randDuration returns a random duration in [lo, hi].
func randDuration(lo, hi time.Duration) time.Duration {
	if hi <= lo {
		return lo
	}
	return lo + rand.N(hi-lo+1)
}
