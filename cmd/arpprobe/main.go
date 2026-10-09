// Command arpprobe checks whether an IPv4 address is free on the local
// network using RFC 5227 address conflict detection, and can then claim it
// with gratuitous ARP announcements.
//
// It needs Linux and root (or CAP_NET_RAW):
//
//	sudo arpprobe -i eth0 -ip 192.168.1.50            # is the address free?
//	sudo arpprobe -i eth0 -ip 192.168.1.50 -announce  # probe, then announce it
//
// Exit status: 0 if free, 1 on error, 2 if the address is in use.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"

	"github.com/mascarenhasmelson/netlib/arp"
)

func main() {
	var (
		ifaceFlag    = flag.String("i", "eth0", "network interface to use")
		ipFlag       = flag.String("ip", "", "IPv4 address to check")
		countFlag    = flag.Int("n", arp.ProbeNum, "number of probes to send")
		announceFlag = flag.Bool("announce", false, "announce the address with gratuitous ARP if it is free")
		strictFlag   = flag.Bool("strict", false, "add the RFC 5227 random initial delay of up to 1s")
	)
	flag.Parse()

	ip, err := netip.ParseAddr(*ipFlag)
	if err != nil || !ip.Is4() {
		log.Fatalf("invalid IPv4 address: %q (use -ip)", *ipFlag)
	}

	ifi, err := net.InterfaceByName(*ifaceFlag)
	if err != nil {
		log.Fatal(err)
	}

	c, err := arp.Dial(ifi)
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	opts := &arp.ProbeOptions{Count: *countFlag}
	if *strictFlag {
		opts.InitialWait = arp.ProbeWait
	}

	fmt.Printf("probing %s on %s ...\n", ip, ifi.Name)
	err = c.Probe(ctx, ip, opts)

	var conflict *arp.ConflictError
	switch {
	case errors.As(err, &conflict):
		fmt.Printf("IN USE: %s is used by %s\n", conflict.IP, conflict.HardwareAddr)
		c.Close()
		os.Exit(2)
	case err != nil:
		log.Fatal(err)
	}
	fmt.Printf("FREE: no device answered for %s\n", ip)

	if *announceFlag {
		if err := c.Announce(ctx, ip, nil); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("announced %s is-at %s\n", ip, ifi.HardwareAddr)
	}
}
