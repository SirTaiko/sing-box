package desync

import "unsafe"

// Documented Windows SDK values read by the present-WLAN query. The complete
// WLAN_CONNECTION_ATTRIBUTES value is 604 bytes:
//
//	isState                    4
//	wlanConnectionMode         4
//	strProfileName[256]      512
//	wlanAssociationAttributes 68   (DOT11_SSID 36 + BSS type 4 + MAC 6 +
//	                                padding 2 + PHY type 4 + PHY index 4 +
//	                                signal quality 4 + RX rate 4 + TX rate 4)
//	wlanSecurityAttributes    16
//
// The SSID actually read here is DOT11_SSID {uSSIDLength; ucSSID[32]} at
// offset 520. Only the documented fields are declared: a synthetic trailing
// array would raise the required size above the documented value and reject a
// correct response, silently losing the SSID.

// wlanAssociationAttributes is WLAN_ASSOCIATION_ATTRIBUTES (68 bytes).
type wlanAssociationAttributes struct {
	SSIDLength    uint32   // uSSIDLength
	SSID          [32]byte // ucSSID[DOT11_SSID_MAX_LENGTH]
	BssType       uint32
	Bssid         [6]byte
	_             [2]byte // natural alignment before the next ULONG
	PhyType       uint32
	PhyIndex      uint32
	SignalQuality uint32
	RxRate        uint32
	TxRate        uint32
}

// wlanSecurityAttributes is WLAN_SECURITY_ATTRIBUTES (16 bytes).
type wlanSecurityAttributes struct {
	SecurityEnabled uint32 // BOOL
	OneXEnabled     uint32 // BOOL
	AuthAlgorithm   uint32 // DOT11_AUTH_ALGORITHM
	CipherAlgorithm uint32 // DOT11_CIPHER_ALGORITHM
}

// wlanConnectionAttributes is WLAN_CONNECTION_ATTRIBUTES (604 bytes).
type wlanConnectionAttributes struct {
	State          uint32 // WLAN_INTERFACE_STATE
	ConnectionMode uint32 // WLAN_CONNECTION_MODE
	ProfileName    [256]uint16
	Association    wlanAssociationAttributes
	Security       wlanSecurityAttributes
}

// wlanSSIDFromValue returns the SSID of one WLAN_CONNECTION_ATTRIBUTES value
// of the given byte size, or the empty string when the provider returned less
// than the documented value. The SSID length is clamped to the 32-byte
// DOT11_SSID buffer, so an overlength field cannot read past the value.
func wlanSSIDFromValue(data unsafe.Pointer, size uint32) string {
	if data == nil || uint64(size) < uint64(unsafe.Sizeof(wlanConnectionAttributes{})) {
		return ""
	}
	connection := (*wlanConnectionAttributes)(data)
	length := int(connection.Association.SSIDLength)
	if length > len(connection.Association.SSID) {
		length = len(connection.Association.SSID)
	}
	if length <= 0 {
		return ""
	}
	return string(connection.Association.SSID[:length])
}
