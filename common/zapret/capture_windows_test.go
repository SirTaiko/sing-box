//go:build windows

package zapret

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"unsafe"
)

// Evaluate ordinary IPv4/IPv6 headers offline with the release DLL itself.
func TestStockCaptureFilter(t *testing.T) {
	exe := os.Getenv("MVPN_TEST_ZAPRET_ENGINE")
	if exe == "" {
		t.Skip("requires the release WinDivert.dll")
	}
	t.Setenv("MVPN_ZAPRET_DEBUG", "")
	lib, err := syscall.LoadDLL(filepath.Join(filepath.Dir(exe), "WinDivert.dll"))
	if err != nil {
		t.Fatal(err)
	}
	defer lib.Release()
	eval, err := lib.FindProc("WinDivertHelperEvalFilter")
	if err != nil {
		t.Fatal(err)
	}
	e := &windowsEngine{options: platformOptions{interfaceIndex: 7, profile: &profile{tokens: []string{profilePortCapture, "--filter-tcp=80,443", "--new", "--filter-udp=8443,40004"}}}}
	for _, protocol := range []string{"tcp", "udp"} {
		e.reservations = append(e.reservations, &portReservation{protocol: protocol, start: 40000, count: 16}, &portReservation{protocol: protocol, start: 41000, count: 16, ipv6: true})
	}
	filter, err := syscall.BytePtrFromString(e.buildFilter())
	if err != nil {
		t.Fatal(err)
	}
	compile, err := lib.FindProc("WinDivertHelperCompileFilter")
	if err != nil {
		t.Fatal(err)
	}
	// Largest number of disjoint ranges kept for both transports, plus
	// the port-zero fallback and IPv4/IPv6 socket reservations.
	e.options.profile = &profile{tokens: []string{profilePortCapture, "--filter-tcp=2-3,5-6,8-9,11-12,14-15,17-18,20-21", "--filter-udp=2-3,5-6,8-9,11-12,14-15,17-18,20-21"}}
	large, err := syscall.BytePtrFromString(e.buildFilter())
	if err != nil {
		t.Fatal(err)
	}
	compiled, _, _ := compile.Call(uintptr(unsafe.Pointer(large)), 0, 0, 0, 0, 0)
	if compiled == 0 {
		t.Fatal("driver rejected the largest permitted filter")
	}

	for _, v6 := range []bool{false, true} {
		for _, out := range []bool{false, true} {
			for _, tc := range []struct {
				proto         byte
				local, remote uint16
				iface         uint32
				expected      bool
			}{
				{6, 40001, 80, 7, true}, {6, 41008, 443, 7, true}, {6, 40001, 81, 7, false}, {6, 40001, 80, 8, false}, {6, 42000, 80, 7, false},
				{17, 40001, 8443, 7, true}, {17, 40001, 81, 7, false}, {17, 40004, 81, 7, true}, {17, 42000, 8443, 7, false},
			} {
				pkt := make([]byte, 60)
				iplen := 20
				if v6 {
					iplen = 40
					pkt[0] = 0x60
					pkt[6] = tc.proto
					pkt[7] = 64
					binary.BigEndian.PutUint16(pkt[4:6], 20)
					copy(pkt[8:24], net.ParseIP("2001:db8::1").To16())
					copy(pkt[24:40], net.ParseIP("2001:db8::2").To16())
				} else {
					pkt = pkt[:40]
					pkt[0] = 0x45
					pkt[9] = tc.proto
					pkt[8] = 64
					binary.BigEndian.PutUint16(pkt[2:4], 40)
					copy(pkt[12:16], net.IPv4(192, 0, 2, 1).To4())
					copy(pkt[16:20], net.IPv4(192, 0, 2, 2).To4())
				}
				src, dst := tc.remote, tc.local
				if out {
					src, dst = dst, src
				}
				binary.BigEndian.PutUint16(pkt[iplen:], src)
				binary.BigEndian.PutUint16(pkt[iplen+2:], dst)
				if tc.proto == 6 {
					pkt[iplen+12] = 0x50
				} else {
					binary.BigEndian.PutUint16(pkt[iplen+4:], 20)
				}
				// WINDIVERT_ADDRESS bitfields precede the layer-dependent union.
				var address [80]byte
				if out {
					address[10] |= 2
				}
				if v6 {
					address[10] |= 16
				}
				binary.LittleEndian.PutUint32(address[16:20], tc.iface)
				match, _, _ := eval.Call(uintptr(unsafe.Pointer(filter)), uintptr(unsafe.Pointer(&pkt[0])), uintptr(len(pkt)), uintptr(unsafe.Pointer(&address[0])))
				if (match != 0) != tc.expected {
					t.Fatalf("IPv6=%v outbound=%v protocol=%d ports %d/%d iface=%d got %v", v6, out, tc.proto, tc.local, tc.remote, tc.iface, match != 0)
				}
			}
		}
	}
}
