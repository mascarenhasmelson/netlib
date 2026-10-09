package arp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/mascarenhasmelson/netlib/ethernet"
)

// ErrPrefixTooLarge is returned by Scan when a prefix contains more addresses
// than ScanOptions.MaxHosts allows.
var ErrPrefixTooLarge = errors.New("arp: prefix has too many addresses to scan")

// Default values used by ScanOptions.
const (
	DefaultScanAttempts = 2
	DefaultScanDelay    = time.Millisecond
	DefaultScanWait     = time.Second
	DefaultScanMaxHosts = 65536
)

// ScanOptions configures Scan. A nil *ScanOptions or a zero field uses the
// defaults.
type ScanOptions struct {
	// Attempts is the number of rounds of requests. Each round after the
	// first only asks addresses that have not answered yet.
	// Zero means DefaultScanAttempts.
	Attempts int

	// Delay is the pause between two requests, which limits how fast the
	// scan floods the network. Zero means DefaultScanDelay.
	Delay time.Duration

	// Wait is how long to listen for late replies after each round.
	// Zero means DefaultScanWait.
	Wait time.Duration

	// MaxHosts guards against scanning huge ranges by mistake: Scan returns
	// ErrPrefixTooLarge if the prefix holds more addresses.
	// Zero means DefaultScanMaxHosts.
	MaxHosts int

	// OnResult, if set, is called once for each newly discovered host as soon
	// as its reply arrives. It runs on an internal goroutine and must not
	// block for long.
	OnResult func(ScanResult)
}

// A ScanResult is a host that answered during a Scan.
type ScanResult struct {
	// IP is the IPv4 address of the host.
	IP netip.Addr

	// HardwareAddr is the hardware address in the first reply for IP.
	HardwareAddr net.HardwareAddr

	// Duplicates lists other hardware addresses that also answered for IP.
	// A non-empty list means two or more devices claim the same address: an
	// IP address conflict.
	Duplicates []net.HardwareAddr
}

// Scan sends an ARP request to every host address in prefix and returns the
// hosts that answered, sorted by IP address. Use LocalPrefix to scan the
// subnet of the Client's interface:
//
//	results, err := c.Scan(ctx, c.LocalPrefix(), nil)
//
// The network and broadcast addresses of prefixes up to /30, and the Client's
// own address, are skipped.
//
// If ctx ends before the scan completes, Scan returns the hosts found so far
// together with ctx.Err().
//
// Scan manages the read deadline of the Client while it runs and clears it
// before returning. It must not be used concurrently with Read or with other
// methods that read, such as ResolveContext and Probe.
func (c *Client) Scan(ctx context.Context, prefix netip.Prefix, opts *ScanOptions) ([]ScanResult, error) {
	o := ScanOptions{
		Attempts: DefaultScanAttempts,
		Delay:    DefaultScanDelay,
		Wait:     DefaultScanWait,
		MaxHosts: DefaultScanMaxHosts,
	}
	if opts != nil {
		if opts.Attempts > 0 {
			o.Attempts = opts.Attempts
		}
		if opts.Delay > 0 {
			o.Delay = opts.Delay
		}
		if opts.Wait > 0 {
			o.Wait = opts.Wait
		}
		if opts.MaxHosts > 0 {
			o.MaxHosts = opts.MaxHosts
		}
		o.OnResult = opts.OnResult
	}

	if !c.ip.IsValid() {
		return nil, errNoIPv4Addr
	}
	if !prefix.IsValid() || !prefix.Addr().Is4() {
		return nil, fmt.Errorf("%w: scan prefix %q", ErrInvalidIP, prefix)
	}

	first, count := hostRange(prefix)
	if count > uint64(o.MaxHosts) {
		return nil, fmt.Errorf("%w: %s has %d addresses, limit is %d",
			ErrPrefixTooLarge, prefix.Masked(), count, o.MaxHosts)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var (
		mu    sync.Mutex
		found = make(map[netip.Addr]*ScanResult)
	)

	r := c.startReader(func(p *Packet, _ *ethernet.Frame) {
		if p.Operation != OperationReply || !prefix.Contains(p.SenderIP) || p.SenderIP == c.ip {
			return
		}

		mu.Lock()
		res, ok := found[p.SenderIP]
		if !ok {
			res = &ScanResult{IP: p.SenderIP, HardwareAddr: p.SenderHardwareAddr}
			found[p.SenderIP] = res
		} else if !bytes.Equal(res.HardwareAddr, p.SenderHardwareAddr) &&
			!slices.ContainsFunc(res.Duplicates, func(hw net.HardwareAddr) bool {
				return bytes.Equal(hw, p.SenderHardwareAddr)
			}) {
			res.Duplicates = append(res.Duplicates, p.SenderHardwareAddr)
		}
		mu.Unlock()

		if !ok && o.OnResult != nil {
			o.OnResult(ScanResult{IP: res.IP, HardwareAddr: res.HardwareAddr})
		}
	})

	scanErr := c.scanRounds(ctx, first, count, o, func(ip netip.Addr) bool {
		mu.Lock()
		defer mu.Unlock()
		_, ok := found[ip]
		return ok
	}, r.done)

	readErr := r.stop()

	mu.Lock()
	results := make([]ScanResult, 0, len(found))
	for _, res := range found {
		results = append(results, ScanResult{
			IP:           res.IP,
			HardwareAddr: res.HardwareAddr,
			Duplicates:   slices.Clone(res.Duplicates),
		})
	}
	mu.Unlock()
	slices.SortFunc(results, func(a, b ScanResult) int { return a.IP.Compare(b.IP) })

	if scanErr != nil {
		return results, scanErr
	}
	return results, readErr
}

// scanRounds sends the requests of each round and waits for replies. It
// returns early if ctx ends or the reader stops.
func (c *Client) scanRounds(ctx context.Context, first netip.Addr, count uint64, o ScanOptions,
	answered func(netip.Addr) bool, readerDone <-chan struct{}) error {
	timer := time.NewTimer(0)
	defer timer.Stop()
	<-timer.C

	wait := func(d time.Duration) error {
		timer.Reset(d)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-readerDone:
			return errReaderStopped
		case <-timer.C:
			return nil
		}
	}

	for range o.Attempts {
		ip := first
		for i := uint64(0); i < count; i, ip = i+1, ip.Next() {
			if ip == c.ip || answered(ip) {
				continue
			}
			if err := c.Request(ip); err != nil {
				return err
			}
			if err := wait(o.Delay); err != nil {
				return ignoreReaderStopped(err)
			}
		}

		if err := wait(o.Wait); err != nil {
			return ignoreReaderStopped(err)
		}
	}

	return nil
}

// errReaderStopped signals that the reader goroutine exited. The reader's own
// error is reported by reader.stop.
var errReaderStopped = errors.New("arp: reader stopped")

func ignoreReaderStopped(err error) error {
	if errors.Is(err, errReaderStopped) {
		return nil
	}
	return err
}

// hostRange returns the first address to scan in prefix and how many
// addresses follow it. Prefixes up to /30 exclude their network and broadcast
// addresses.
func hostRange(prefix netip.Prefix) (netip.Addr, uint64) {
	prefix = prefix.Masked()
	first := prefix.Addr()
	count := uint64(1) << (32 - prefix.Bits())
	if prefix.Bits() <= 30 {
		first = first.Next()
		count -= 2
	}
	return first, count
}
