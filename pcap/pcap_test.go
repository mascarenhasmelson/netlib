package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
	"time"
)

var (
	frame1 = []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0, 0, 0, 0, 1, 0x08, 0x06, 1, 2, 3, 4}
	frame2 = bytes.Repeat([]byte{0xab}, 1500)
	ts1    = time.Date(2026, 10, 8, 12, 0, 0, 123456789, time.UTC)
	ts2    = time.Date(2026, 10, 8, 12, 0, 1, 500, time.UTC)
)

func TestRoundTripMicroseconds(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewWriter(&buf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if w.LinkType() != LinkTypeEthernet {
		t.Fatalf("default link type %d", w.LinkType())
	}
	if err := w.WritePacket(ts1, frame1); err != nil {
		t.Fatal(err)
	}
	if err := w.WritePacket(ts2, frame2); err != nil {
		t.Fatal(err)
	}

	if want := 24 + 16 + len(frame1) + 16 + len(frame2); buf.Len() != want {
		t.Fatalf("file is %d bytes, want %d", buf.Len(), want)
	}

	r, err := NewReader(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if r.LinkType() != LinkTypeEthernet || r.SnapLen() != DefaultSnapLen || r.Nanosecond() {
		t.Fatalf("header: link %d snap %d nano %t", r.LinkType(), r.SnapLen(), r.Nanosecond())
	}
	if major, minor := r.Version(); major != 2 || minor != 4 {
		t.Fatalf("version %d.%d", major, minor)
	}

	data, ci, err := r.ReadPacket()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, frame1) || ci.CaptureLength != len(frame1) || ci.Length != len(frame1) {
		t.Fatalf("packet 1: %x %+v", data, ci)
	}
	// Microsecond files keep microseconds: 123456789ns becomes 123456000ns.
	if want := ts1.Truncate(time.Microsecond); !ci.Timestamp.Equal(want) {
		t.Fatalf("timestamp %v, want %v", ci.Timestamp, want)
	}

	data, ci, err = r.ReadPacket()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, frame2) || !ci.Timestamp.Equal(ts2.Truncate(time.Microsecond)) {
		t.Fatalf("packet 2 mismatch: %d bytes at %v", len(data), ci.Timestamp)
	}

	if _, _, err := r.ReadPacket(); err != io.EOF {
		t.Fatalf("after last packet: got %v, want io.EOF", err)
	}
}

func TestRoundTripNanoseconds(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewWriter(&buf, &WriterOptions{Nanosecond: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WritePacket(ts1, frame1); err != nil {
		t.Fatal(err)
	}

	r, err := NewReader(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Nanosecond() {
		t.Fatal("nanosecond flag lost")
	}
	_, ci, err := r.ReadPacket()
	if err != nil {
		t.Fatal(err)
	}
	if !ci.Timestamp.Equal(ts1) {
		t.Fatalf("timestamp %v, want exactly %v", ci.Timestamp, ts1)
	}
}

func TestSnapLenTruncates(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewWriter(&buf, &WriterOptions{SnapLen: 64, LinkType: LinkTypeRaw})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WritePacket(ts1, frame2); err != nil {
		t.Fatal(err)
	}

	r, err := NewReader(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if r.LinkType() != LinkTypeRaw || r.SnapLen() != 64 {
		t.Fatalf("header: link %d snap %d", r.LinkType(), r.SnapLen())
	}
	data, ci, err := r.ReadPacket()
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 64 || ci.CaptureLength != 64 || ci.Length != 1500 {
		t.Fatalf("got %d bytes, CaptureLength %d, Length %d; want 64, 64, 1500", len(data), ci.CaptureLength, ci.Length)
	}
}

func TestWritePacketInfoKeepsOriginalLength(t *testing.T) {
	var buf bytes.Buffer
	w, _ := NewWriter(&buf, nil)
	// The caller only kept the first 18 bytes of a 900 byte packet.
	if err := w.WritePacketInfo(CaptureInfo{Timestamp: ts1, Length: 900}, frame1); err != nil {
		t.Fatal(err)
	}
	r, _ := NewReader(&buf)
	_, ci, err := r.ReadPacket()
	if err != nil || ci.Length != 900 || ci.CaptureLength != len(frame1) {
		t.Fatalf("got %+v, %v", ci, err)
	}
}

func TestReadBigEndianFile(t *testing.T) {
	// A file written on a big-endian machine, built by hand.
	var b bytes.Buffer
	hdr := make([]byte, 24)
	binary.BigEndian.PutUint32(hdr[0:4], magicMicroseconds)
	binary.BigEndian.PutUint16(hdr[4:6], 2)
	binary.BigEndian.PutUint16(hdr[6:8], 4)
	binary.BigEndian.PutUint32(hdr[16:20], 65535)
	binary.BigEndian.PutUint32(hdr[20:24], 1)
	b.Write(hdr)

	rec := make([]byte, 16)
	binary.BigEndian.PutUint32(rec[0:4], 1700000000)
	binary.BigEndian.PutUint32(rec[4:8], 250000) // 0.25s in microseconds
	binary.BigEndian.PutUint32(rec[8:12], uint32(len(frame1)))
	binary.BigEndian.PutUint32(rec[12:16], uint32(len(frame1)))
	b.Write(rec)
	b.Write(frame1)

	r, err := NewReader(&b)
	if err != nil {
		t.Fatal(err)
	}
	data, ci, err := r.ReadPacket()
	if err != nil {
		t.Fatal(err)
	}
	if want := time.Unix(1700000000, 250000000); !ci.Timestamp.Equal(want) || !bytes.Equal(data, frame1) {
		t.Fatalf("got %v %x", ci.Timestamp, data)
	}
}

func TestKnownFileBytes(t *testing.T) {
	// The exact header and record layout tcpdump writes on little-endian
	// machines, so other tools can read our files.
	var buf bytes.Buffer
	w, _ := NewWriter(&buf, nil)
	_ = w.WritePacket(time.Unix(0x01020304, 5000), []byte{0xaa, 0xbb})

	want := []byte{
		0xd4, 0xc3, 0xb2, 0xa1, // magic
		0x02, 0x00, 0x04, 0x00, // version 2.4
		0, 0, 0, 0, 0, 0, 0, 0, // thiszone, sigfigs
		0x00, 0x00, 0x04, 0x00, // snaplen 262144
		0x01, 0x00, 0x00, 0x00, // LINKTYPE_ETHERNET
		0x04, 0x03, 0x02, 0x01, // ts_sec
		0x05, 0x00, 0x00, 0x00, // ts_usec = 5
		0x02, 0x00, 0x00, 0x00, // incl_len
		0x02, 0x00, 0x00, 0x00, // orig_len
		0xaa, 0xbb,
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("file bytes:\n got % x\nwant % x", buf.Bytes(), want)
	}
}

func TestNotPcap(t *testing.T) {
	inputs := map[string][]byte{
		"empty":       nil,
		"short":       {0xd4, 0xc3},
		"text":        []byte("this is definitely not a capture file"),
		"pcapng":      {0x0a, 0x0d, 0x0d, 0x0a, 0x1c, 0, 0, 0, 0x4d, 0x3c, 0x2b, 0x1a, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		"bad version": {0xd4, 0xc3, 0xb2, 0xa1, 0x09, 0, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0, 0},
	}
	for name, in := range inputs {
		if _, err := NewReader(bytes.NewReader(in)); !errors.Is(err, ErrNotPcap) {
			t.Errorf("%s: got %v, want ErrNotPcap", name, err)
		}
	}
}

func TestTruncatedFile(t *testing.T) {
	var buf bytes.Buffer
	w, _ := NewWriter(&buf, nil)
	_ = w.WritePacket(ts1, frame2)
	full := buf.Bytes()

	// Cut inside the record header and inside the packet data.
	for _, cut := range []int{24 + 5, 24 + 16 + 100} {
		r, err := NewReader(bytes.NewReader(full[:cut]))
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := r.ReadPacket(); err != io.ErrUnexpectedEOF {
			t.Errorf("cut at %d: got %v, want io.ErrUnexpectedEOF", cut, err)
		}
	}
}

func TestRecordTooLarge(t *testing.T) {
	var buf bytes.Buffer
	w, _ := NewWriter(&buf, &WriterOptions{SnapLen: 128})
	_ = w.WritePacket(ts1, frame1)
	b := buf.Bytes()
	// Corrupt incl_len to claim 1 GiB.
	binary.LittleEndian.PutUint32(b[24+8:24+12], 1<<30)

	r, err := NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.ReadPacket(); !errors.Is(err, ErrRecordTooLarge) {
		t.Fatalf("got %v, want ErrRecordTooLarge", err)
	}
}

func TestWriterError(t *testing.T) {
	errDisk := errors.New("disk full")
	if _, err := NewWriter(failWriter{errDisk}, nil); !errors.Is(err, errDisk) {
		t.Fatalf("got %v", err)
	}
}

type failWriter struct{ err error }

func (f failWriter) Write([]byte) (int, error) { return 0, f.err }

func FuzzReader(f *testing.F) {
	var buf bytes.Buffer
	w, _ := NewWriter(&buf, nil)
	_ = w.WritePacket(ts1, frame1)
	f.Add(buf.Bytes())
	f.Add([]byte{0xa1, 0xb2, 0x3c, 0x4d, 0, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 1})

	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := NewReader(bytes.NewReader(b))
		if err != nil {
			return
		}
		for range 100 {
			if _, _, err := r.ReadPacket(); err != nil {
				return
			}
		}
	})
}
