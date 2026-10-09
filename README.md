# netlib

Low-level Ethernet, VLAN and ARP networking for Go, in a single module.
Everything you need to build, parse, send and capture raw network frames, with
no third-party GitHub dependencies (only Go's official `golang.org/x` packages).

```
go get github.com/mascarenhasmelson/netlib
```

Requires Go 1.26 or newer.

## Contents

- [Packages at a glance](#packages-at-a-glance)
- [Platform support](#platform-support)
- [ethernet: Ethernet II frames](#ethernet-ethernet-ii-frames)
- [ethernet: VLAN tags (802.1Q and Q-in-Q)](#ethernet-vlan-tags-8021q-and-q-in-q)
- [arp: Address Resolution Protocol](#arp-address-resolution-protocol)
  - [Resolve with retries](#resolve-with-retries-resolvecontext)
  - [Subnet scan](#subnet-scan-scan)
  - [IP conflict detection and announcements (RFC 5227)](#ip-conflict-detection-and-announcements-rfc-5227)
- [pcap: capture files for Wireshark and tcpdump](#pcap-capture-files-for-wireshark-and-tcpdump)
- [packet: raw Linux packet sockets](#packet-raw-linux-packet-sockets)
- [socket: low-level sockets with Go deadlines](#socket-low-level-sockets-with-go-deadlines)
- [Command-line tools](#command-line-tools)
- [Running the examples](#running-the-examples)
- [Offline builds and development](#offline-builds-and-development)

## Packages at a glance

| Package | Import path | Use it to |
|---|---|---|
| `ethernet` | `github.com/mascarenhasmelson/netlib/ethernet` | Build and parse Ethernet II frames, VLAN tags and checksums |
| `arp` | `github.com/mascarenhasmelson/netlib/arp` | Build and parse ARP packets; find the MAC address of an IP (with retries); scan a subnet for devices; detect IP conflicts; announce addresses; answer ARP requests |
| `pcap` | `github.com/mascarenhasmelson/netlib/pcap` | Write and read `.pcap` capture files for Wireshark and tcpdump |
| `packet` | `github.com/mascarenhasmelson/netlib/packet` | Send and capture raw frames on a Linux network interface |
| `socket` | `github.com/mascarenhasmelson/netlib/socket` | Use any socket type through system calls, with Go deadlines and context cancellation |

How they fit together:

```
arp ──────► ethernet          (ARP packets travel inside Ethernet frames)
  │
  └───────► packet ──► socket ──► golang.org/x/sys/unix
                 └──────────────► golang.org/x/net/bpf   (kernel filters)

pcap                          (standalone: stores frames from any source)
```

You can use any package on its own. For example, `ethernet` and `pcap` have
no dependencies at all, and `packet` works without `arp`.

## Platform support

| | Linux | macOS / BSD | Windows |
|---|---|---|---|
| `ethernet` (frames, VLANs, checksums) | yes | yes | yes |
| `pcap` (capture files) | yes | yes | yes |
| `arp.Packet`, `arp.NewPacket` (encode/decode) | yes | yes | yes |
| `arp.Dial`, `arp.Client` (live network: resolve, scan, probe, announce) | yes | compiles, returns error | compiles, returns error |
| `packet` | yes | compiles, returns error | compiles, returns error |
| `socket` | yes | yes | not available |

"Returns error" means calls fail with `packet: not implemented on <os>`, so a
program that imports these packages still builds everywhere. Raw sockets need
root or the `CAP_NET_RAW` capability.

---

## ethernet: Ethernet II frames

**What it is for:** every packet on a wired or Wi-Fi LAN travels inside an
Ethernet frame: destination MAC, source MAC, a type field (EtherType) saying
what is inside, and the payload. This package turns a Go struct into those
bytes and back.

**What it offers**

| API | Purpose |
|---|---|
| `Frame{Destination, Source, ServiceVLAN, VLAN, EtherType, Payload}` | One Ethernet II frame |
| `(*Frame).MarshalBinary()` | Encode to bytes; pads short payloads to the 46 byte minimum |
| `(*Frame).UnmarshalBinary(b)` | Decode bytes, including any VLAN tags |
| `(*Frame).MarshalFCS()` / `UnmarshalFCS(b)` | Encode/decode with the 4 byte CRC32 frame check sequence and verify it |
| `Broadcast` | The `ff:ff:ff:ff:ff:ff` address that reaches every host |
| `EtherTypeIPv4`, `EtherTypeARP`, `EtherTypeIPv6`, `EtherTypeVLAN`, `EtherTypeServiceVLAN` | Common EtherType values; `EtherType` prints as a readable name |
| 24 more named EtherTypes | See the table below |
| `ErrInvalidFCS` | Returned when a checksum does not match |

**Named EtherTypes.** Every constant below prints as its name, so logs show
`EtherTypeLLDP` instead of `EtherType(35020)`:

| Constant | Value | Protocol |
|---|---|---|
| `EtherTypeIPv4` / `EtherTypeIPv6` | `0x0800` / `0x86DD` | Internet Protocol |
| `EtherTypeARP` / `EtherTypeRARP` | `0x0806` / `0x8035` | Address resolution, reverse ARP |
| `EtherTypeVLAN` / `EtherTypeServiceVLAN` / `EtherTypeQinQ` | `0x8100` / `0x88A8` / `0x9100` | 802.1Q, 802.1ad, legacy Q-in-Q tags |
| `EtherTypeWakeOnLAN` | `0x0842` | Wake-on-LAN magic packet |
| `EtherTypeLLDP` | `0x88CC` | Link Layer Discovery Protocol |
| `EtherTypeEAPOL` | `0x888E` | 802.1X port authentication |
| `EtherTypeMACsec` | `0x88E5` | 802.1AE MAC security |
| `EtherTypePTP` | `0x88F7` | IEEE 1588 Precision Time Protocol |
| `EtherTypeMPLSUnicast` / `EtherTypeMPLSMulticast` | `0x8847` / `0x8848` | MPLS |
| `EtherTypePPPoEDiscovery` / `EtherTypePPPoESession` | `0x8863` / `0x8864` | PPP over Ethernet (DSL) |
| `EtherTypeMACControl` | `0x8808` | Flow control pause frames |
| `EtherTypeSlowProtocols` | `0x8809` | LACP link aggregation |
| `EtherTypeCFM` | `0x8902` | 802.1ag connectivity fault management |
| `EtherTypePBB` | `0x88E7` | 802.1ah provider backbone bridging |
| `EtherTypePRP` / `EtherTypeHSR` | `0x88FB` / `0x892F` | Industrial redundancy protocols |
| `EtherTypeFCoE` / `EtherTypeFCoEInit` | `0x8906` / `0x8914` | Fibre Channel over Ethernet |
| `EtherTypeRoCE` | `0x8915` | RDMA over Converged Ethernet |
| `EtherTypeHomePlug` | `0x88E1` | HomePlug AV powerline |
| `EtherTypeAppleTalk` / `EtherTypeIPX` | `0x809B` / `0x8137` | Legacy protocols |
| `EtherTypeLoopback` | `0x9000` | Ethernet loopback testing |

**Extras:** pure Go with no system calls, so it runs anywhere and is easy to
unit test; implements `encoding.BinaryMarshaler`/`BinaryUnmarshaler`; decoding
never panics on short or malformed input, it returns `io.ErrUnexpectedEOF`.

**Example** ([examples/ethernet](examples/ethernet/main.go))

```go
f := &ethernet.Frame{
	Destination: ethernet.Broadcast,
	Source:      net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
	EtherType:   ethernet.EtherTypeIPv4,
	Payload:     []byte("hello, ethernet"),
}

// Encode for sending.
b, err := f.MarshalBinary()

// Decode what you received.
var got ethernet.Frame
err = got.UnmarshalBinary(b)
fmt.Println(got.Source, got.Destination, got.EtherType)

// Add and verify a CRC32 checksum.
withFCS, err := f.MarshalFCS()
err = got.UnmarshalFCS(withFCS) // ethernet.ErrInvalidFCS if corrupted
```

Output of `go run ./examples/ethernet`:

```
encoded 60 bytes, header: ff ff ff ff ff ff 02 00 00 00 00 01 08 00
decoded: 02:00:00:00:00:01 -> ff:ff:ff:ff:ff:ff, type EtherTypeIPv4, payload "hello, ethernet"
with FCS: 64 bytes, checksum 5f 1f 95 37
FCS verified
corrupted frame rejected: invalid frame check sequence
```

---

## ethernet: VLAN tags (802.1Q and Q-in-Q)

**What it is for:** VLANs split one physical network into separate virtual
networks. A 4 byte tag inside the frame carries the VLAN ID and a traffic
priority. Service providers stack two tags (802.1ad "Q-in-Q"): an outer
provider tag around the customer's tag.

**What it offers**

| API | Purpose |
|---|---|
| `VLAN{Priority, DropEligible, ID}` | One 802.1Q tag. ID 0-4094, priority 0-7 |
| `Frame.VLAN` | Customer tag (C-VLAN), TPID `0x8100` |
| `Frame.ServiceVLAN` | Provider tag (S-VLAN), TPID `0x88a8`; requires `Frame.VLAN` too |
| `(*VLAN).MarshalBinary()` / `UnmarshalBinary(b)` | Encode/decode a single 2 byte tag |
| `PriorityBackground` ... `PriorityNetworkControl` | Named IEEE 802.1p priority levels (voice, video, ...) |
| `VLANNone`, `VLANMax` | Special IDs: 0 means priority only, 4095 is reserved |
| `ErrInvalidVLAN` | Returned for out-of-range IDs/priorities or an S-VLAN without a C-VLAN |

**Extras:** tags are added and removed automatically by `Frame` marshaling, so
code that handles untagged frames works unchanged on tagged ones; values are
validated on both encode and decode.

**Example** ([examples/vlan](examples/vlan/main.go))

```go
// Single tag: VLAN 100, voice priority.
f := &ethernet.Frame{
	Destination: ethernet.Broadcast,
	Source:      src,
	VLAN:        &ethernet.VLAN{Priority: ethernet.PriorityVoice, ID: 100},
	EtherType:   ethernet.EtherTypeIPv4,
	Payload:     []byte("tagged"),
}
b, err := f.MarshalBinary()

// Q-in-Q: provider VLAN 300 carrying customer VLAN 100.
qinq := &ethernet.Frame{
	Destination: ethernet.Broadcast,
	Source:      src,
	ServiceVLAN: &ethernet.VLAN{ID: 300},
	VLAN:        &ethernet.VLAN{ID: 100, DropEligible: true},
	EtherType:   ethernet.EtherTypeARP,
}

// Reading tags from a received frame.
var got ethernet.Frame
err = got.UnmarshalBinary(b)
if got.VLAN != nil {
	fmt.Println("VLAN", got.VLAN.ID, "priority", got.VLAN.Priority)
}
```

Output of `go run ./examples/vlan`:

```
802.1Q tag bytes: 81 00 a0 64
decoded VLAN 100, priority 5, inner type EtherTypeIPv4
Q-in-Q: S-VLAN 300, C-VLAN 100 (drop eligible true), inner type EtherTypeARP
standalone tag for VLAN 42 / priority 4: 80 2a
VLAN 4095 rejected: invalid VLAN
```

---

## arp: Address Resolution Protocol

**What it is for:** before a computer can send to an IPv4 address on its LAN,
it must learn that host's MAC address. It broadcasts an ARP request ("who has
192.168.1.1?") and the owner replies ("192.168.1.1 is at aa:bb:..."). This
package builds and parses those packets and can perform the whole exchange on
a real interface. Typical uses: network scanners, finding devices, detecting
IP conflicts, proxy ARP, and testing network equipment.

**What it offers**

| API | Purpose |
|---|---|
| `NewPacket(op, srcMAC, srcIP, dstMAC, dstIP)` | Build a validated request or reply |
| `Packet` + `MarshalBinary()` / `UnmarshalBinary(b)` | The RFC 826 packet and its byte encoding |
| `OperationRequest`, `OperationReply` | ARP operations; print as readable names |
| `Dial(ifi)` | Open an ARP client on an interface (Linux) |
| `(*Client).Resolve(ip)` | Send one request and wait for the MAC address (bounded by `SetDeadline`) |
| `(*Client).ResolveContext(ctx, ip, opts)` | **New.** Resolve with automatic retries and context cancellation |
| `(*Client).Scan(ctx, prefix, opts)` | **New.** Find every device in a subnet, and report IP conflicts |
| `(*Client).Probe(ctx, ip, opts)` | **New.** RFC 5227 check: is this IP address free to use? |
| `(*Client).Announce(ctx, ip, opts)` | **New.** RFC 5227 gratuitous ARP: tell the network an IP is now at this MAC |
| `(*Client).Request(ip)` | Send a request without waiting |
| `(*Client).Read()` | Receive the next ARP packet and its Ethernet frame |
| `(*Client).Reply(req, mac, ip)` | Answer a request |
| `(*Client).WriteTo(p, mac)` | Send any custom ARP packet |
| `(*Client).IP()`, `LocalPrefix()` | **New.** The client's IPv4 address and subnet, e.g. `192.168.1.0/24` |
| `HardwareAddr()`, `InterfaceName()` | The interface's MAC address and name |
| `SetDeadline`, `SetReadDeadline`, `SetWriteDeadline` | Timeouts, like `net.Conn` |
| `New(ifi, conn)` | Build a client on your own `net.PacketConn`, useful for tests |
| `ErrInvalidHardwareAddr`, `ErrInvalidIP` | Validation errors |
| `ErrNoResponse`, `ErrPrefixTooLarge`, `ErrAddressInUse`, `ConflictError` | **New.** Errors from the new features; check with `errors.Is` / `errors.As` |

**Extras:** uses `net/netip` addresses; ignores non-ARP traffic for you; works
with any hardware address length (e.g. 20 byte InfiniBand); reads frames up to
the interface MTU, so jumbo frames work; the packet encoder is fuzz tested.

**Example: build and parse packets (any OS)** ([examples/arp](examples/arp/main.go))

```go
myMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
myIP := netip.MustParseAddr("192.168.1.10")
routerIP := netip.MustParseAddr("192.168.1.1")

// "Who has 192.168.1.1? Tell 192.168.1.10"
req, err := arp.NewPacket(arp.OperationRequest, myMAC, myIP, ethernet.Broadcast, routerIP)

// ARP rides inside an Ethernet frame with EtherType 0x0806.
payload, err := req.MarshalBinary()
frame := &ethernet.Frame{
	Destination: ethernet.Broadcast,
	Source:      myMAC,
	EtherType:   ethernet.EtherTypeARP,
	Payload:     payload,
}
wire, err := frame.MarshalBinary()

// Parse it back.
var gotFrame ethernet.Frame
err = gotFrame.UnmarshalBinary(wire)
var gotReq arp.Packet
err = gotReq.UnmarshalBinary(gotFrame.Payload)
```

**Example: find a MAC address on the live network (Linux, root)**

```go
ifi, err := net.InterfaceByName("eth0")
c, err := arp.Dial(ifi)
if err != nil {
	log.Fatal(err)
}
defer c.Close()

c.SetDeadline(time.Now().Add(2 * time.Second))
mac, err := c.Resolve(netip.MustParseAddr("192.168.1.1"))
fmt.Println(mac) // e.g. 00:15:5d:1a:cb:c0
```

**Example: answer ARP requests (proxy ARP)**

```go
for {
	pkt, eth, err := c.Read()
	if err != nil {
		log.Fatal(err)
	}
	if pkt.Operation == arp.OperationRequest && pkt.TargetIP == myIP {
		log.Printf("%s asked for %s via %s", pkt.SenderIP, pkt.TargetIP, eth.Source)
		c.Reply(pkt, c.HardwareAddr(), myIP)
	}
}
```

Output of `sudo ./arp -i eth0 -ip 172.30.144.1 -scan -probe 172.30.144.1` on Linux:

```
request: who-has 192.168.1.1 tell 192.168.1.10
on the wire: 60 bytes (28 byte ARP packet + header + padding)
reply:   192.168.1.1 is-at 02:00:00:00:00:fe (OperationReply)
live:    using eth0, 172.30.146.177/20
live:    172.30.144.1 is-at 00:15:5d:1a:cb:c0 (Resolve)
live:    172.30.144.1 is-at 00:15:5d:1a:cb:c0 (ResolveContext)
scan:    1 devices on 172.30.144.0/20 in 12.491s
scan:      172.30.144.1    00:15:5d:1a:cb:c0
probe:   172.30.144.1 is IN USE by 00:15:5d:1a:cb:c0
```

### Resolve with retries (`ResolveContext`)

`Resolve` sends a single request, so one lost packet means a failed lookup.
`ResolveContext` resends the request if no reply arrives in time, and stops
as soon as the context is canceled or times out.

| `ResolveOptions` field | Default | Meaning |
|---|---|---|
| `Attempts` | 3 | Maximum number of requests sent |
| `Interval` | 1s | How long to wait for a reply before resending |

```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

mac, err := c.ResolveContext(ctx, netip.MustParseAddr("192.168.1.1"), nil) // nil = defaults
switch {
case errors.Is(err, arp.ErrNoResponse):
	fmt.Println("host is down or not on this network")
case errors.Is(err, context.DeadlineExceeded):
	fmt.Println("gave up after 5s")
case err != nil:
	log.Fatal(err)
default:
	fmt.Println("MAC:", mac)
}
```

### Subnet scan (`Scan`)

Finds every device on a network by asking each address in turn, like the
`arp-scan` tool. Because devices must answer ARP to communicate at all, this
finds machines that block ping. It also spots **IP conflicts**: two devices
answering for the same address.

How it works: one request per address, with a small delay to avoid flooding
the network; replies are collected in the background; a second round re-asks
only the addresses that stayed silent; the network address, broadcast address
and your own address are skipped.

| `ScanOptions` field | Default | Meaning |
|---|---|---|
| `Attempts` | 2 | Rounds of requests; later rounds only ask silent addresses |
| `Delay` | 1ms | Pause between requests (a /24 takes about 0.3s per round) |
| `Wait` | 1s | How long to wait for late replies after each round |
| `MaxHosts` | 65536 | Refuse larger ranges (a /16 is the biggest by default) |
| `OnResult` | nil | Called as each device is found, to show live progress |

```go
// Scan the subnet of the interface, e.g. 192.168.1.0/24.
results, err := c.Scan(ctx, c.LocalPrefix(), nil)

// Or any subnet, with live progress.
results, err = c.Scan(ctx, netip.MustParsePrefix("10.0.5.0/24"), &arp.ScanOptions{
	OnResult: func(r arp.ScanResult) { fmt.Println("found", r.IP, r.HardwareAddr) },
})

for _, r := range results { // sorted by IP
	fmt.Println(r.IP, r.HardwareAddr)
	if len(r.Duplicates) > 0 {
		fmt.Println("  IP CONFLICT: also claimed by", r.Duplicates)
	}
}
```

If the context is canceled mid-scan, `Scan` returns the devices found so far
together with the context error.

### IP conflict detection and announcements (RFC 5227)

Two devices with the same IP address break each other's connections. RFC 5227
defines how a device checks an address before using it, and how it then
announces it. This is what DHCP clients, operating systems and failover
systems (keepalived, VRRP) do.

**`Probe`** sends 3 ARP probes, 1–2 seconds apart, with sender IP `0.0.0.0` so
they do not disturb anyone's ARP cache, then listens 2 more seconds. Any
device that answers for the address, announces it, or is probing for it at
the same moment is a conflict.

| `ProbeOptions` field | Default | Meaning |
|---|---|---|
| `Count` | 3 | Number of probes |
| `MinInterval`, `MaxInterval` | 1s, 2s | Random delay between probes |
| `Wait` | 2s | Listening time after the last probe |
| `InitialWait` | 0 | Random delay before the first probe; set `arp.ProbeWait` for strict RFC timing |

**`Announce`** broadcasts gratuitous ARP packets (2 by default, 2 seconds apart)
saying "this IP is now at my MAC", so every device updates its ARP cache
immediately. Use it after `Probe` succeeds, after changing an address, or to
take over an address during failover. Only announce addresses you own:
announcing someone else's address redirects their traffic to you.

| `AnnounceOptions` field | Default | Meaning |
|---|---|---|
| `Count` | 2 | Number of announcements |
| `Interval` | 2s | Delay between announcements |

```go
ip := netip.MustParseAddr("192.168.1.50")

err := c.Probe(ctx, ip, nil)
var conflict *arp.ConflictError
switch {
case errors.As(err, &conflict):
	fmt.Println("in use by", conflict.HardwareAddr) // errors.Is(err, arp.ErrAddressInUse) is also true
case err != nil:
	log.Fatal(err)
default:
	fmt.Println("free, claiming it")
	if err := c.Announce(ctx, ip, nil); err != nil {
		log.Fatal(err)
	}
}
```

The timing constants from the RFC are exported: `ProbeWait`, `ProbeNum`,
`ProbeMin`, `ProbeMax`, `AnnounceWait`, `AnnounceNum`, `AnnounceInterval`.

Captured with `examples/packet -w` and read back with `tcpdump -r`, a probe
followed by an announcement looks like this on the wire:

```
Request who-has 172.30.146.177 tell 0.0.0.0, length 46          <- probe 1
Request who-has 172.30.146.177 tell 0.0.0.0, length 46          <- probe 2 (1-2s later)
Request who-has 172.30.146.177 tell 0.0.0.0, length 46          <- probe 3
Request who-has 172.30.146.177 tell 172.30.146.177, length 46   <- announcement
```

**Using these features together.** `ResolveContext`, `Scan` and `Probe` read
from the client in the background while they run. Use one at a time per
client, not at the same time as `Read`. Open a second client with `arp.Dial`
if you need them in parallel.

---

## pcap: capture files for Wireshark and tcpdump

**What it is for:** saving packets to a file you can open in Wireshark, share
with others or analyse later, and reading captures made by tcpdump or
Wireshark into your program. It uses the classic libpcap `.pcap` format that
every network tool understands.

**What it offers**

| API | Purpose |
|---|---|
| `NewWriter(w, opts)` | Start a capture file on any `io.Writer`, e.g. an `*os.File` |
| `(*Writer).WritePacket(ts, data)` | Append one packet with its capture time |
| `(*Writer).WritePacketInfo(ci, data)` | Append a packet that was already truncated, keeping its original length |
| `WriterOptions{LinkType, SnapLen, Nanosecond}` | Link type (Ethernet by default), maximum bytes per packet, nanosecond timestamps |
| `NewReader(r)` | Open a capture file; detects byte order and timestamp precision |
| `(*Reader).ReadPacket()` | Next packet and its `CaptureInfo`; `io.EOF` at the end |
| `CaptureInfo{Timestamp, CaptureLength, Length}` | When the packet was seen, bytes stored, original size |
| `LinkType()`, `SnapLen()`, `Version()`, `Nanosecond()` | File header details |
| `LinkTypeEthernet`, `LinkTypeRaw`, `LinkTypeLinuxSLL`, `LinkType80211`, `LinkTypeNull` | Common link types |
| `ErrNotPcap`, `ErrRecordTooLarge` | Errors for invalid or corrupt files |

**Extras:** pure Go, works on every OS; reads files from big- and
little-endian machines; corrupt files return errors instead of crashing or
allocating huge buffers (the reader is fuzz tested); output verified to be
byte-for-byte what tcpdump expects.

**Example: save a live capture** (from [examples/packet](examples/packet/main.go))

```go
f, err := os.Create("arp.pcap")
defer f.Close()
w, err := pcap.NewWriter(f, nil) // Ethernet, microsecond timestamps

n, _, err := conn.ReadFrom(buf) // from packet.Listen
err = w.WritePacket(time.Now(), buf[:n])
```

**Example: decode a capture file** ([examples/pcap](examples/pcap/main.go))

```go
f, err := os.Open("capture.pcap")
defer f.Close()
r, err := pcap.NewReader(f)

for {
	data, ci, err := r.ReadPacket()
	if errors.Is(err, io.EOF) {
		break
	}
	if err != nil {
		log.Fatal(err)
	}

	var fr ethernet.Frame
	if err := fr.UnmarshalBinary(data); err == nil {
		fmt.Println(ci.Timestamp, fr.Source, "->", fr.Destination, fr.EtherType)
	}
}
```

Output of `go run ./examples/pcap` (writes `demo.pcap`, then decodes it):

```
wrote 3 frames to demo.pcap (open it in Wireshark)
reading demo.pcap: pcap 2.4, link type 1, snaplen 262144
  1  12:09:46.247728    60 bytes  02:00:00:00:00:01 -> ff:ff:ff:ff:ff:ff EtherTypeARP: who-has 192.168.1.1 tell 192.168.1.10
  2  12:09:46.248728    60 bytes  02:00:00:00:00:fe -> 02:00:00:00:00:01 EtherTypeARP: 192.168.1.1 is-at 02:00:00:00:00:fe
  3  12:09:46.249728    64 bytes  02:00:00:00:00:01 -> 02:00:00:00:00:fe EtherTypeIPv4 vlan 100 prio 5
```

---

## packet: raw Linux packet sockets

**What it is for:** normal sockets only show you TCP/UDP data. Linux packet
sockets (`AF_PACKET`) give you whole frames straight from the network card,
and let you send frames you built yourself. This is how tcpdump, DHCP
clients, LLDP agents and custom protocols work. `arp.Client` is built on it.

**What it offers**

| API | Purpose |
|---|---|
| `Listen(ifi, packet.Raw, etherType, cfg)` | Open a socket that sees full frames including the Ethernet header |
| `Listen(ifi, packet.Datagram, etherType, cfg)` | Same, but the kernel strips/adds the header for you |
| `Config{Filter}` | Attach a BPF filter before binding, so no unwanted packet slips through |
| `(*Conn).ReadFrom` / `WriteTo` | Receive/send frames; it is a standard `net.PacketConn` |
| `Addr{HardwareAddr}` | The MAC address to send to / received from |
| `(*Conn).SetBPF(filter)` | Change the kernel filter on an open socket |
| `(*Conn).SetPromiscuous(true)` | See traffic addressed to other machines |
| `(*Conn).JoinGroup(mac)` / `LeaveGroup(mac)` | Receive Ethernet multicast groups (e.g. LLDP `01:80:c2:00:00:0e`) |
| `(*Conn).Stats()` | Kernel counters: packets delivered, dropped |
| `SetDeadline` and friends | Timeouts, like any `net.Conn` |
| `(*Conn).SyscallConn()` | Raw file descriptor access for custom socket options |

**Extras:** integrates with Go's network poller, so thousands of goroutines can
wait on sockets cheaply and `Close` unblocks pending reads; BPF filters run in
the kernel so filtered traffic costs almost nothing; errors are standard
`*net.OpError` values.

**Example: capture ARP frames like `tcpdump arp`** ([examples/packet](examples/packet/main.go))

```go
// Kernel filter: keep only frames whose EtherType (offset 12) is ARP.
filter, err := bpf.Assemble([]bpf.Instruction{
	bpf.LoadAbsolute{Off: 12, Size: 2},
	bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: uint32(ethernet.EtherTypeARP), SkipTrue: 1},
	bpf.RetConstant{Val: 65535}, // keep
	bpf.RetConstant{Val: 0},     // drop
})

const etherTypeAll = 0x0003 // every protocol
c, err := packet.Listen(ifi, packet.Raw, etherTypeAll, &packet.Config{Filter: filter})
defer c.Close()

buf := make([]byte, ifi.MTU+14)
c.SetReadDeadline(time.Now().Add(10 * time.Second))
n, from, err := c.ReadFrom(buf)

var f ethernet.Frame
f.UnmarshalBinary(buf[:n])
fmt.Println(from, f.Source, "->", f.Destination, f.EtherType)

// Send a frame you built yourself.
out, _ := (&ethernet.Frame{
	Destination: ethernet.Broadcast,
	Source:      ifi.HardwareAddr,
	EtherType:   0xcccc,
	Payload:     []byte("hello from netlib"),
}).MarshalBinary()
c.WriteTo(out, &packet.Addr{HardwareAddr: ethernet.Broadcast})
```

Output of `sudo ./packet -i eth0 -n 2` on Linux:

```
capturing 2 ARP frames on eth0 (00:15:5d:23:f7:63)
42 bytes from 00:15:5d:23:f7:63: 00:15:5d:23:f7:63 -> ff:ff:ff:ff:ff:ff EtherTypeARP
42 bytes from 00:15:5d:1a:cb:c0: 00:15:5d:1a:cb:c0 -> 00:15:5d:23:f7:63 EtherTypeARP
kernel stats: 2 packets, 0 drops
sent one broadcast frame
```

---

## socket: low-level sockets with Go deadlines

**What it is for:** Go's `net` package only covers TCP, UDP, IP and Unix
sockets. When you need another socket family (netlink, packet, vsock, CAN, KCM)
or a system call `net` does not expose, you normally fall back to raw file
descriptors and lose deadlines, cancellation and goroutine-friendly blocking.
`socket` gives you raw system calls *and* keeps all of that. It is the
foundation `packet` is built on; most applications use `packet` or `arp`
instead, but it is there when you need to go lower.

**What it offers**

| API | Purpose |
|---|---|
| `Socket(domain, type, proto, name, cfg)` | Open any socket, e.g. `unix.AF_INET`, `unix.AF_NETLINK`, `unix.AF_VSOCK` |
| `New(fd, name)` / `FileConn(f, name)` | Wrap a file descriptor you already have |
| `Bind`, `Listen`, `Accept`, `Connect`, `Shutdown` | Classic socket calls; blocking ones take a `context.Context` |
| `Sendto`, `Recvfrom`, `Sendmsg`, `Recvmsg`, `SendmsgBuffers` | Datagram and message I/O with control data (OOB) |
| `Read`/`Write`, `ReadContext`/`WriteContext` | Stream I/O, implements `io.Reader`/`io.Writer` |
| `Getsockname`, `Getpeername` | Local and remote addresses |
| `GetsockoptInt/String/Bytes`, `SetsockoptInt/String/Bytes` | Socket options |
| `SetBPF`, `RemoveBPF`, `SetsockoptPacketMreq`, `GetsockoptTpacketStats` | Linux filters, multicast membership and packet statistics |
| `SetReadBuffer`, `SetWriteBuffer`, `ReadBuffer`, `WriteBuffer` | Kernel buffer sizes |
| `Ioctl`, `ReadFunc`, `WriteFunc`, `SyscallConn` | Escape hatches for any system call, still poller-aware |
| `Config{NetNS}` | Open the socket inside a Linux network namespace |
| Linux extras: `PidfdGetfd`, `PidfdSendSignal`, `Waitid`, `IoctlKCM*` | pidfd and Kernel Connection Multiplexor helpers |

**Extras:** every blocking call honours both `SetDeadline` and context
cancellation/timeouts; `Close` immediately unblocks goroutines waiting on the
socket; errors are wrapped as `*os.SyscallError` with the call name.

**Example: UDP ping-pong with system calls** ([examples/socket](examples/socket/main.go))

```go
//go:build unix

server, err := socket.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0, "udp-server", nil)
defer server.Close()
server.Bind(&unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}})
sa, _ := server.Getsockname()
addr := sa.(*unix.SockaddrInet4)

server.SetsockoptInt(unix.SOL_SOCKET, unix.SO_RCVBUF, 1<<20)

client, err := socket.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0, "udp-client", nil)
defer client.Close()

// Blocking calls wait on Go's poller and respect the context.
ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
defer cancel()

client.Sendto(ctx, []byte("ping"), 0, addr)

buf := make([]byte, 64)
n, from, err := server.Recvfrom(ctx, buf, 0)
server.Sendto(ctx, []byte("pong"), 0, from)

// Nothing more is coming: this returns context.DeadlineExceeded after 200ms.
short, cancelShort := context.WithTimeout(context.Background(), 200*time.Millisecond)
defer cancelShort()
_, _, err = server.Recvfrom(short, buf, 0)
```

Output of `go run ./examples/socket` on Linux (no root needed):

```
server listening on 127.0.0.1:59869
receive buffer: 2097152 bytes
server got "ping" from port 41615
client got "pong"
read timed out as expected: recvfrom: context deadline exceeded
```

Files that import `socket` should carry a `//go:build unix` (or `linux`) line,
since the package does not exist on Windows.

---

## Command-line tools

Ready-made programs built on the library:

| Command | What it does | Example |
|---|---|---|
| `cmd/arpc` | Look up the MAC address of an IPv4 address, retrying lost requests (`-r` attempts, `-d` wait each) | `sudo arpc -i eth0 -ip 192.168.1.1` |
| `cmd/arpscan` | **New.** List every device on a subnet and flag IP conflicts | `sudo arpscan -i eth0` |
| `cmd/arpprobe` | **New.** Check if an IP is free (RFC 5227); `-announce` claims it. Exit code 0 = free, 2 = in use | `sudo arpprobe -i eth0 -ip 192.168.1.50` |
| `cmd/proxyarpd` | Answer ARP requests for an IP on behalf of another host | `sudo proxyarpd -i eth0 -ip 192.168.1.50` |
| `cmd/etherecho` | Broadcast a message with a custom EtherType and print messages from others | `sudo etherecho -i eth0 -m hello` |

`arpscan` options: `-s 10.0.0.0/24` scans another subnet, `-r` sets rounds,
`-d` the delay between requests, `-w` the wait for late replies, `-t` an
overall time limit, and `-max` the largest subnet allowed. Ctrl+C stops the
scan and still prints the results. Real output on a WSL network:

```
$ sudo arpscan -i eth0
scanning 172.30.144.0/20 on eth0 (172.30.146.177, 00:15:5d:23:f5:da)
  found 172.30.144.1     00:15:5d:1a:cb:c0

IP ADDRESS       MAC ADDRESS        NOTE
172.30.144.1     00:15:5d:1a:cb:c0

1 hosts up, 0 conflicts, scanned in 12.267s

$ sudo arpprobe -i eth0 -ip 172.30.144.1
probing 172.30.144.1 on eth0 ...
IN USE: 172.30.144.1 is used by 00:15:5d:1a:cb:c0

$ sudo arpprobe -i eth0 -ip 172.30.150.222
probing 172.30.150.222 on eth0 ...
FREE: no device answered for 172.30.150.222
```

Install on Linux:

```
go install github.com/mascarenhasmelson/netlib/cmd/arpscan@latest
go install github.com/mascarenhasmelson/netlib/cmd/arpprobe@latest
go install github.com/mascarenhasmelson/netlib/cmd/arpc@latest
```

Or build on Windows for Linux:

```
$env:GOOS="linux"; $env:GOARCH="amd64"; go build -o arpc ./cmd/arpc
```

## Running the examples

All examples live in [`examples/`](examples):

| Example | Runs on | Command |
|---|---|---|
| `examples/ethernet` | any OS | `go run ./examples/ethernet` |
| `examples/vlan` | any OS | `go run ./examples/vlan` |
| `examples/arp` | any OS (live part: Linux + root) | `go run ./examples/arp`, then `sudo ./arp -i eth0 -ip 192.168.1.1 -scan -probe 192.168.1.50` |
| `examples/pcap` | any OS | `go run ./examples/pcap` or `go run ./examples/pcap -r capture.pcap` |
| `examples/packet` | Linux + root | `sudo ./packet -i eth0 -n 5` (`-p` promiscuous, `-w arp.pcap` save to file) |
| `examples/socket` | Linux, macOS, BSD | `go run ./examples/socket` |

From Windows, build Linux binaries and run them in WSL:

```
$env:GOOS="linux"; $env:GOARCH="amd64"; go build -o packet ./examples/packet
wsl -u root ./packet -i eth0 -n 2
```

## Offline builds and development

`vendor/` holds copies of the `golang.org/x` dependencies, so building and
testing inside this repository needs no network access. Projects that import
netlib download those dependencies normally through the Go module proxy.

```
go vet ./...
go test ./...
```

Tests that need Linux (in `packet` and `socket`) only run on Linux. From
Windows: `GOOS=linux go test -c ./socket` and run the binary inside WSL.

The ARP features are tested without a real network using a simulated LAN
(`arp/fakelan_test.go`): fake hosts answer requests, can drop packets to test
retries, and can share an IP to test conflict detection. Fuzz tests cover the
ARP packet decoder and the pcap reader:

```
go test ./pcap -run '^$' -fuzz FuzzReader -fuzztime 30s
go test ./arp -run '^$' -fuzz FuzzPacketUnmarshalMarshal -fuzztime 30s
```

## License

MIT. See [LICENSE.md](LICENSE.md). Based on the MIT-licensed `arp`,
`ethernet`, `packet` and `socket` packages by Matt Layher.
