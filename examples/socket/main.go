//go:build unix

// Command socket shows the socket package: a raw file descriptor socket that
// still gets Go-style deadlines and context cancellation. It builds a UDP
// echo over localhost using system calls directly, so it runs without root on
// Linux, macOS and BSD (not Windows).
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/mascarenhasmelson/netlib/socket"
	"golang.org/x/sys/unix"
)

func main() {
	// 1. Open sockets with any domain/type/protocol, here UDP over IPv4.
	// The name is used in error messages.
	server, err := socket.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0, "udp-server", nil)
	if err != nil {
		log.Fatal(err)
	}
	defer server.Close()

	// 2. Plain system call wrappers: bind(2), getsockname(2), setsockopt(2).
	if err := server.Bind(&unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		log.Fatal(err)
	}
	sa, err := server.Getsockname()
	if err != nil {
		log.Fatal(err)
	}
	addr := sa.(*unix.SockaddrInet4)
	fmt.Printf("server listening on 127.0.0.1:%d\n", addr.Port)

	if err := server.SetsockoptInt(unix.SOL_SOCKET, unix.SO_RCVBUF, 1<<20); err != nil {
		log.Fatal(err)
	}
	rcvbuf, _ := server.GetsockoptInt(unix.SOL_SOCKET, unix.SO_RCVBUF)
	fmt.Printf("receive buffer: %d bytes\n", rcvbuf)

	client, err := socket.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0, "udp-client", nil)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// 3. Every blocking call takes a context: it waits on Go's network
	// poller instead of blocking an OS thread, and can be cancelled.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := client.Sendto(ctx, []byte("ping"), 0, addr); err != nil {
		log.Fatal(err)
	}

	buf := make([]byte, 64)
	n, from, err := server.Recvfrom(ctx, buf, 0)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("server got %q from port %d\n", buf[:n], from.(*unix.SockaddrInet4).Port)

	if err := server.Sendto(ctx, []byte("pong"), 0, from); err != nil {
		log.Fatal(err)
	}
	n, _, err = client.Recvfrom(ctx, buf, 0)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("client got %q\n", buf[:n])

	// 4. Timeouts: nothing else is coming, so this read gives up after
	// 200ms instead of blocking forever.
	short, cancelShort := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancelShort()
	if _, _, err := server.Recvfrom(short, buf, 0); errors.Is(err, context.DeadlineExceeded) {
		fmt.Println("read timed out as expected:", err)
	}
}
