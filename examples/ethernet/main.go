// Command ethernet shows how to build, encode, decode and checksum Ethernet II
// frames with the ethernet package. It runs on any operating system.
package main

import (
	"errors"
	"fmt"
	"log"
	"net"

	"github.com/mascarenhasmelson/netlib/ethernet"
)

func main() {
	// 1. Build a frame: destination, source, EtherType and payload.
	f := &ethernet.Frame{
		Destination: ethernet.Broadcast,
		Source:      net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		EtherType:   ethernet.EtherTypeIPv4,
		Payload:     []byte("hello, ethernet"),
	}

	// 2. Encode it into bytes ready to send on the wire. Short payloads are
	// zero padded to the 46 byte Ethernet minimum automatically.
	b, err := f.MarshalBinary()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("encoded %d bytes, header: % x\n", len(b), b[:14])

	// 3. Decode bytes received from the network back into a Frame.
	var got ethernet.Frame
	if err := got.UnmarshalBinary(b); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("decoded: %s -> %s, type %s, payload %q\n",
		got.Source, got.Destination, got.EtherType, got.Payload[:15])

	// 4. Optional frame check sequence (CRC32), for when the OS or NIC does
	// not add or verify it for you.
	withFCS, err := f.MarshalFCS()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("with FCS: %d bytes, checksum % x\n", len(withFCS), withFCS[len(withFCS)-4:])

	if err := got.UnmarshalFCS(withFCS); err != nil {
		log.Fatal(err)
	}
	fmt.Println("FCS verified")

	// A corrupted frame is rejected with ErrInvalidFCS.
	withFCS[20] ^= 0xff
	if err := got.UnmarshalFCS(withFCS); errors.Is(err, ethernet.ErrInvalidFCS) {
		fmt.Println("corrupted frame rejected:", err)
	}
}
