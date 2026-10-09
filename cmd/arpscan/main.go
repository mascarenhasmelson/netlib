// Command arpscan discovers every device on a local network by sending an ARP
// request to each address in a subnet, and reports IP address conflicts.
//
// It needs Linux and root (or CAP_NET_RAW):
//
//	sudo arpscan -i eth0                    # scan the interface's own subnet
//	sudo arpscan -i eth0 -s 192.168.1.0/24  # scan a specific subnet
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/mascarenhasmelson/netlib/arp"
)

func main() {
	var (
		ifaceFlag   = flag.String("i", "eth0", "network interface to scan from")
		subnetFlag  = flag.String("s", "", "subnet to scan in CIDR form (default: the interface's subnet)")
		retriesFlag = flag.Int("r", arp.DefaultScanAttempts, "rounds of requests; later rounds only ask silent addresses")
		delayFlag   = flag.Duration("d", arp.DefaultScanDelay, "pause between requests")
		waitFlag    = flag.Duration("w", arp.DefaultScanWait, "time to wait for late replies after each round")
		timeoutFlag = flag.Duration("t", 0, "stop the whole scan after this long (0: no limit)")
		maxFlag     = flag.Int("max", arp.DefaultScanMaxHosts, "refuse subnets with more addresses than this")
	)
	flag.Parse()

	ifi, err := net.InterfaceByName(*ifaceFlag)
	if err != nil {
		log.Fatal(err)
	}

	c, err := arp.Dial(ifi)
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	prefix := c.LocalPrefix()
	if *subnetFlag != "" {
		prefix, err = netip.ParsePrefix(*subnetFlag)
		if err != nil {
			log.Fatalf("invalid subnet %q: %v", *subnetFlag, err)
		}
	}
	if !prefix.IsValid() {
		log.Fatal("could not determine the interface subnet; pass one with -s")
	}

	// Ctrl+C stops the scan and still prints what was found.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if *timeoutFlag > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *timeoutFlag)
		defer cancel()
	}

	fmt.Printf("scanning %s on %s (%s, %s)\n", prefix.Masked(), ifi.Name, c.IP(), ifi.HardwareAddr)
	start := time.Now()

	results, err := c.Scan(ctx, prefix, &arp.ScanOptions{
		Attempts: *retriesFlag,
		Delay:    *delayFlag,
		Wait:     *waitFlag,
		MaxHosts: *maxFlag,
		OnResult: func(r arp.ScanResult) {
			fmt.Printf("  found %-15s  %s\n", r.IP, r.HardwareAddr)
		},
	})
	if err != nil && len(results) == 0 {
		log.Fatal(err)
	}

	fmt.Printf("\n%-15s  %-17s  %s\n", "IP ADDRESS", "MAC ADDRESS", "NOTE")
	conflicts := 0
	for _, r := range results {
		note := ""
		if len(r.Duplicates) > 0 {
			conflicts++
			others := make([]string, len(r.Duplicates))
			for i, d := range r.Duplicates {
				others[i] = d.String()
			}
			note = "IP CONFLICT, also claimed by " + strings.Join(others, ", ")
		}
		fmt.Printf("%-15s  %-17s  %s\n", r.IP, r.HardwareAddr, note)
	}

	fmt.Printf("\n%d hosts up, %d conflicts, scanned in %s\n",
		len(results), conflicts, time.Since(start).Round(time.Millisecond))
	if err != nil {
		fmt.Println("scan stopped early:", err)
	}
}
