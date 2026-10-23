package desync

import (
	"testing"
	"unsafe"
)

// TestWLANConnectionAttributesDocumentedSize pins the documented Windows SDK
// value layout used by the present-WLAN query. WLAN_CONNECTION_ATTRIBUTES is
// 604 bytes and the SSID starts at offset 520; a synthetic trailing array
// (the shipped 620-byte prefix) makes a correct 604-byte response unusable and
// silently loses the SSID.
func TestWLANConnectionAttributesDocumentedSize(t *testing.T) {
	if got := unsafe.Sizeof(wlanConnectionAttributes{}); got != 604 {
		t.Fatalf("WLAN_CONNECTION_ATTRIBUTES size = %d, want 604", got)
	}
	if got := unsafe.Sizeof(wlanAssociationAttributes{}); got != 68 {
		t.Fatalf("WLAN_ASSOCIATION_ATTRIBUTES size = %d, want 68", got)
	}
	if got := unsafe.Sizeof(wlanSecurityAttributes{}); got != 16 {
		t.Fatalf("WLAN_SECURITY_ATTRIBUTES size = %d, want 16", got)
	}
	// SSID starts at offset 520 and the DOT11_SSID length field at 524.
	var value wlanConnectionAttributes
	if got := unsafe.Offsetof(value.Association); got != 520 {
		t.Fatalf("association offset = %d, want 520", got)
	}
	if got := uintptr(unsafe.Pointer(&value.Association.SSIDLength)) - uintptr(unsafe.Pointer(&value)); got != 520 {
		t.Fatalf("uSSIDLength offset = %d, want 520", got)
	}
	if got := uintptr(unsafe.Pointer(&value.Association.SSID)) - uintptr(unsafe.Pointer(&value)); got != 524 {
		t.Fatalf("ucSSID offset = %d, want 524", got)
	}
}

// TestWLANSSIDFromValueLengthControls pins the exact-size accepted response and
// the length/truncation controls around it.
func TestWLANSSIDFromValueLengthControls(t *testing.T) {
	newValue := func(length uint32, ssid string) *wlanConnectionAttributes {
		value := new(wlanConnectionAttributes)
		value.Association.SSIDLength = length
		copy(value.Association.SSID[:], ssid)
		return value
	}
	size := uint32(unsafe.Sizeof(wlanConnectionAttributes{}))

	// Exact documented 604-byte value: the SSID (and therefore MatchSSID) must
	// be preserved. On the shipped 620-byte requirement this returns "".
	if got := wlanSSIDFromValue(unsafe.Pointer(newValue(3, "lab")), size); got != "lab" {
		t.Fatalf("604-byte value SSID = %q, want %q", got, "lab")
	}
	// An oversized extension is still a valid response.
	if got := wlanSSIDFromValue(unsafe.Pointer(newValue(3, "lab")), size+16); got != "lab" {
		t.Fatalf("oversized value SSID = %q, want %q", got, "lab")
	}
	// A truncated response must not be read at all.
	if got := wlanSSIDFromValue(unsafe.Pointer(newValue(3, "lab")), size-1); got != "" {
		t.Fatalf("truncated value SSID = %q, want empty", got)
	}
	if got := wlanSSIDFromValue(nil, size); got != "" {
		t.Fatalf("nil value SSID = %q, want empty", got)
	}
	// 0, 32 and overlength SSID fields, with the 32-byte bound.
	if got := wlanSSIDFromValue(unsafe.Pointer(newValue(0, "")), size); got != "" {
		t.Fatalf("zero-length SSID = %q, want empty", got)
	}
	full := "0123456789abcdefghijklmnopqrstuv"
	if len(full) != 32 {
		t.Fatalf("fixture length = %d", len(full))
	}
	if got := wlanSSIDFromValue(unsafe.Pointer(newValue(32, full)), size); got != full {
		t.Fatalf("32-byte SSID = %q, want %q", got, full)
	}
	if got := wlanSSIDFromValue(unsafe.Pointer(newValue(64, full)), size); got != full {
		t.Fatalf("overlength SSID = %q, want the clamped %q", got, full)
	}
}
