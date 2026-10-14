package tlsdesync

import (
	"bytes"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

// Run this compiled test binary as root in the disposable test VM. The peer
// must receive exactly the original ClientHello and subsequent application
// bytes; this checks real kernel reassembly and NFQUEUE lifecycle, not a mock.
func TestIntegrationStream(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires CAP_NET_ADMIN/CAP_NET_RAW; run in test VM")
	}
	hello := realHello(t)
	configs := []Options{
		{Mode: "multisplit", Split: "1,midsld"},
		{Mode: "multisplit", Split: "1", Overlap: 681, FakeSNI: "www.google.com"},
		{Mode: "multidisorder", Split: "1,midsld"},
		{Mode: "multidisorder", Split: "1,midsld", Overlap: 568, FakeSNI: "www.google.com"},
		{Mode: "multidisorder", FakeSNI: "www.google.com", FakeRepeats: 11, FakeMethod: "wrong-sequence"},
		{Mode: "multisplit", FakeSNI: "www.google.com", FakeRepeats: 6, FakeMethod: "wrong-checksum"},
		{Mode: "multisplit", FakeSNI: "www.google.com", FakeRepeats: 6, FakeMethod: "wrong-md5"},
		{Mode: "multidisorder", FakeSNI: "www.google.com", FakeRepeats: 6, FakeMethod: "wrong-ack"},
	}
	for _, options := range configs {
		t.Run(options.Mode+"/"+options.FakeMethod+"/"+options.Split, func(t *testing.T) {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			want := append(append([]byte(nil), hello...), []byte("application-data-after-hello")...)
			peer := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					peer <- err
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(4 * time.Second))
				got := make([]byte, len(want))
				_, err = io.ReadFull(conn, got)
				if err == nil && !bytes.Equal(got, want) {
					err = io.ErrUnexpectedEOF
				}
				if err == nil {
					_, err = conn.Write([]byte("peer-ok"))
				}
				peer <- err
			}()
			raw, err := net.Dial("tcp4", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			conn, err := NewConn(raw, options)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(4 * time.Second))
			if _, err = conn.Write(hello); err != nil {
				t.Fatal(err)
			}
			if _, err = conn.Write(want[len(hello):]); err != nil {
				t.Fatal(err)
			}
			response := make([]byte, 7)
			if _, err = io.ReadFull(conn, response); err != nil || string(response) != "peer-ok" {
				t.Fatalf("peer response: %q, %v", response, err)
			}
			if err = <-peer; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestIntegrationCloseInterruptsDelay(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires test VM root")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	raw, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	peer, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	conn, err := NewConn(raw, Options{FakeSNI: "www.google.com", FakeRepeats: 16, SegmentDelayMS: 500})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Write(realHello(t)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	start := time.Now()
	if err = conn.Close(); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("Close waited for the full delayed packet batch")
	}
}
