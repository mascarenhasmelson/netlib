package arp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/mascarenhasmelson/netlib/ethernet"
)

// ErrNoResponse is returned by ResolveContext when no reply arrives after
// every attempt. Use errors.Is to check for it.
var ErrNoResponse = errors.New("arp: no response")

// Default values used by ResolveOptions.
const (
	DefaultResolveAttempts = 3
	DefaultResolveInterval = time.Second
)

// ResolveOptions configures ResolveContext. A nil *ResolveOptions or a zero
// field uses the defaults.
type ResolveOptions struct {
	// Attempts is the maximum number of ARP requests to send.
	// Zero means DefaultResolveAttempts.
	Attempts int

	// Interval is how long to wait for a reply after each request before
	// sending the next one. Zero means DefaultResolveInterval.
	Interval time.Duration
}

// ResolveContext performs an ARP request like Resolve, but resends the
// request if no reply arrives within opts.Interval, up to opts.Attempts
// times, and stops early when ctx is canceled or its deadline passes.
//
// It returns ctx.Err() if ctx ends first, and an error matching ErrNoResponse
// if every attempt went unanswered.
//
// ResolveContext manages the read deadline of the Client while it runs and
// clears it before returning. Like Resolve, it must not be used concurrently
// with Read or with other methods that read, such as Scan and Probe.
func (c *Client) ResolveContext(ctx context.Context, ip netip.Addr, opts *ResolveOptions) (net.HardwareAddr, error) {
	attempts, interval := DefaultResolveAttempts, DefaultResolveInterval
	if opts != nil {
		if opts.Attempts > 0 {
			attempts = opts.Attempts
		}
		if opts.Interval > 0 {
			interval = opts.Interval
		}
	}

	if !c.ip.IsValid() {
		return nil, errNoIPv4Addr
	}
	if !ip.Is4() {
		return nil, ErrInvalidIP
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	replies := make(chan net.HardwareAddr, 1)
	r := c.startReader(func(p *Packet, _ *ethernet.Frame) {
		if p.Operation != OperationReply || p.SenderIP != ip {
			return
		}
		select {
		case replies <- p.SenderHardwareAddr:
		default:
		}
	})
	defer r.stop()

	timer := time.NewTimer(0)
	defer timer.Stop()
	<-timer.C

	for range attempts {
		if err := c.Request(ip); err != nil {
			return nil, err
		}

		timer.Reset(interval)
		select {
		case mac := <-replies:
			return mac, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-r.done:
			return nil, r.stop()
		case <-timer.C:
		}
	}

	return nil, fmt.Errorf("%w from %s after %d attempts", ErrNoResponse, ip, attempts)
}

// A reader reads ARP packets from a Client in a background goroutine.
type reader struct {
	c    *Client
	done chan struct{} // closed when the goroutine exits

	mu       sync.Mutex
	stopping bool
	err      error

	once sync.Once
}

// startReader clears the Client's read deadline and calls fn for every ARP
// packet received until stop is called or reading fails. fn runs on the
// reader goroutine.
func (c *Client) startReader(fn func(p *Packet, f *ethernet.Frame)) *reader {
	r := &reader{c: c, done: make(chan struct{})}
	if err := c.p.SetReadDeadline(time.Time{}); err != nil {
		r.err = err
		close(r.done)
		return r
	}

	go func() {
		defer close(r.done)
		for {
			p, f, err := c.Read()
			if err == nil {
				fn(p, f)
				continue
			}

			// The lock orders this check against stop, so a stale timeout
			// can never clear the deadline stop uses to unblock us.
			r.mu.Lock()
			if r.stopping {
				if !isTimeout(err) {
					r.err = err
				}
				r.mu.Unlock()
				return
			}
			if isTimeout(err) {
				// The deadline was set elsewhere: clear it and keep reading.
				if derr := c.p.SetReadDeadline(time.Time{}); derr == nil {
					r.mu.Unlock()
					continue
				}
			}
			r.err = err
			r.mu.Unlock()
			return
		}
	}()

	return r
}

// stop unblocks and waits for the reader goroutine, clears the read deadline,
// and returns the first read error other than the timeout used to stop it.
// It is safe to call more than once.
func (r *reader) stop() error {
	r.once.Do(func() {
		// A deadline in the past makes the blocked read return immediately.
		r.mu.Lock()
		r.stopping = true
		_ = r.c.p.SetReadDeadline(time.Unix(1, 0))
		r.mu.Unlock()

		<-r.done
		_ = r.c.p.SetReadDeadline(time.Time{})
	})

	r.mu.Lock()
	defer r.mu.Unlock()
	return r.err
}

// isTimeout reports whether err is a read deadline timeout.
func isTimeout(err error) bool {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
