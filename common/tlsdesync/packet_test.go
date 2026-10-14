package tlsdesync

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"testing"

	tf "github.com/sagernet/sing-box/common/tlsfragment"
)

func realHello(t *testing.T) []byte {
	t.Helper()
	a, b := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = tls.Client(a, &tls.Config{ServerName: "www.youtube.com", CurvePreferences: []tls.CurveID{tls.X25519}}).Handshake()
	}()
	header := make([]byte, 5)
	if _, err := io.ReadFull(b, header); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, binary.BigEndian.Uint16(header[3:5]))
	if _, err := io.ReadFull(b, payload); err != nil {
		t.Fatal(err)
	}
	b.Close()
	a.Close()
	<-done
	return append(header, payload...)
}

func TestCloneHelloPreservesSessionAndShape(t *testing.T) {
	real := realHello(t)
	for _, name := range []string{"a.io", "www.google.com", "a-much-longer-hostname.example.com"} {
		fake, err := cloneHello(real, name)
		if err != nil {
			t.Fatal(err)
		}
		sni := tf.IndexTLSServerName(fake)
		if sni == nil || sni.ServerName != name {
			t.Fatalf("invalid fake SNI: %+v", sni)
		}
		sessionEnd := 44 + int(real[43])
		if !bytes.Equal(real[43:sessionEnd], fake[43:sessionEnd]) || bytes.Equal(real[11:43], fake[11:43]) {
			t.Fatal("session ID changed or random was not changed")
		}
		original := tf.IndexTLSServerName(real)
		if !bytes.Equal(real[original.Index+original.Length:], fake[sni.Index+sni.Length:]) {
			t.Fatal("extensions after SNI changed")
		}
	}
	for i := 0; i < len(real); i++ {
		if _, err := cloneHello(real[:i], "www.google.com"); err == nil {
			t.Fatalf("accepted truncated hello at %d", i)
		}
	}
}

func TestPacketStrategiesPreserveStream(t *testing.T) {
	hello := realHello(t)
	frame := make([]byte, 40+len(hello))
	frame[0], frame[8], frame[9], frame[32], frame[33] = 0x45, 64, 6, 5<<4, 0x18
	copy(frame[12:16], []byte{192, 0, 2, 1})
	copy(frame[16:20], []byte{198, 51, 100, 1})
	binary.BigEndian.PutUint16(frame[2:4], uint16(len(frame)))
	copy(frame[40:], hello)
	for _, seq := range []uint32{42, 0xfffffff0} {
		binary.BigEndian.PutUint32(frame[24:28], seq)
		for _, mode := range []string{"multisplit", "multidisorder"} {
			for _, overlap := range []int{0, 568, 681} {
				for _, method := range []string{"wrong-sequence", "wrong-checksum", "wrong-ack", "wrong-md5", "ttl"} {
					o := Options{Mode: mode, Split: "1,midsld", Overlap: overlap, FakeSNI: "www.google.com", FakeRepeats: 3, FakeMethod: method, FakeTTL: 5}
					packets, err := o.packets(frame)
					if err != nil {
						t.Fatal(err)
					}
					stream, seen := make([]byte, len(hello)), make([]bool, len(hello))
					for i, p := range packets {
						start, err := packetPayload(p)
						if err != nil || checksum(p[:20], 0) != 0 {
							t.Fatal("invalid IP packet")
						}
						pseudo := uint32(6 + len(p) - 20)
						for j := 12; j < 20; j += 2 {
							pseudo += uint32(binary.BigEndian.Uint16(p[j : j+2]))
						}
						if (checksum(p[20:], pseudo) == 0) == (i < 3 && method == "wrong-checksum") {
							t.Fatalf("incorrect TCP checksum for %s", method)
						}
						if i < o.FakeRepeats {
							continue
						}
						offset := int(int32(binary.BigEndian.Uint32(p[24:28]) - seq))
						for j, value := range p[start:] {
							at := offset + j
							if at >= 0 && at < len(stream) {
								stream[at], seen[at] = value, true
							}
						}
					}
					if !bytes.Equal(stream, hello) {
						t.Fatal("server stream differs from original")
					}
					for _, present := range seen {
						if !present {
							t.Fatal("missing stream byte")
						}
					}
				}
			}
		}
	}
}
