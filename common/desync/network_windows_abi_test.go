//go:build windows

package desync

// Permanent regressions for the native Windows network probe:
//   * an absent optional wlanapi.dll is an ordinary capability error and never a
//     LazyProc.Call panic, while NLM/adapter state stays usable;
//   * the typed COM call sites use the vtable slots netlistmgr.h declares (the
//     shipped defects dispatched GetNetworks to a property-getter slot and read
//     INetwork state from the wrong members);
//   * the present-capability WLAN path still enumerates and matches.
//
// The slot proof here is structural; network_windows_inetwork_mapping_test.go
// drives the same call sites with distinct values and is the behavioral proof.

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

const vtableSlot = unsafe.Sizeof(uintptr(0))

// iNetworkHeaderOrder is the member order netlistmgr.h declares for INetwork
// (IID DCB00002-570F-4A9B-8D69-199FDBA5723B), index 0 = vtable slot 7 because
// the interface derives from IDispatch (3 IUnknown + 4 IDispatch entries).
//
// Provenance, independent of the production struct:
//   - the SDK interface definition as reflected by the SDK-generated Win32
//     metadata bindings: windows-docs-rs Win32/Networking/NetworkListManager
//     trait INetwork_Impl requires these 13 methods in this order;
//   - an independent COM binding of the same header, tailscale
//     wgengine/winnet INetworkVtbl, which declares the same sequence;
//   - native slot probes on the test guest, where slots 13 (interface pointer),
//     14 (four DWORD out-parameters), 17 (NLM_CONNECTIVITY bitmask, not an enum)
//     and 18 (a live getter beyond the shipped 17-slot struct) are only
//     consistent with this tail.
//
// The table is the authority the production struct is checked against. It is
// deliberately not derived from that struct: spelling a field in the wrong
// place is exactly the defect this file must catch.
var iNetworkHeaderOrder = []string{
	"get_Name",                   // 7
	"put_Name",                   // 8
	"get_Description",            // 9
	"put_Description",            // 10
	"get_NetworkId",              // 11
	"get_DomainType",             // 12
	"get_NetworkConnections",     // 13
	"GetTimeCreatedAndConnected", // 14
	"get_IsConnectedToInternet",  // 15
	"get_IsConnected",            // 16
	"get_Connectivity",           // 17
	"get_Category",               // 18
	"put_Category",               // 19
}

// iNetworkListManagerHeaderOrder is the INetworkListManager member prefix that
// this body dispatches through (IID DCB00000-570F-4A9B-8D69-199FDBA5723B).
var iNetworkListManagerHeaderOrder = []string{
	"GetNetworks",           // 7
	"GetNetwork",            // 8
	"GetNetworkConnections", // 9
	"GetNetworkConnection",  // 10
	"get_IsConnectedToInternet",
	"get_IsConnected",
	"get_Connectivity",
}

// headerSlot returns the vtable slot of one member of an IDispatch-derived
// interface, given its 0-based position in the header order.
func headerSlot(index int) uintptr { return uintptr(7 + index) }

// iNetworkRequiredMembers are the INetwork members this body declares and
// dispatches through. Slots 8-10 (put_Name, get_Description, put_Description)
// are an explicit unnamed gap in the production struct and put_Category (19)
// is not declared at all: nothing on this side writes a network property, and
// the layout is not enlarged with dead members just to mirror the whole header.
// Those members are therefore not required, while the header order above still
// fixes the numeric slot of every member that *is* declared.
var iNetworkRequiredMembers = []string{
	"get_Name",                   // 7
	"get_NetworkId",              // 11
	"get_DomainType",             // 12
	"get_NetworkConnections",     // 13
	"GetTimeCreatedAndConnected", // 14
	"get_IsConnectedToInternet",  // 15
	"get_IsConnected",            // 16
	"get_Connectivity",           // 17
	"get_Category",               // 18
}

// iNetworkListManagerRequiredMembers are the manager members this body
// declares: the four call sites plus the two trailing [propget] VARIANT_BOOL
// getters, which the struct declares for a complete and reviewable prefix
// without calling them. get_Connectivity (slot 13) is deliberately not
// declared, so it is not required either.
var iNetworkListManagerRequiredMembers = []string{
	"GetNetworks",               // 7
	"GetNetwork",                // 8
	"GetNetworkConnections",     // 9
	"GetNetworkConnection",      // 10
	"get_IsConnectedToInternet", // 11
	"get_IsConnected",           // 12
}

// checkMemberSlots compares a member name -> vtable byte offset map against the
// members this body is required to declare, with the header order as the slot
// authority (index 0 = slot 7). It returns one line per member that is missing,
// not a header member at all, or at a different slot than the header gives it.
//
// The declared set must be exactly the required set: a field that disappears,
// is renamed, or is added without being accounted for here is reported, so the
// check cannot be satisfied by mapping a subset of the interface. An empty
// result means the mapping is exact.
func checkMemberSlots(order []string, required []string, offsets map[string]uintptr) []string {
	var problems []string
	seen := make(map[string]bool, len(required))
	for _, member := range required {
		index := slices.Index(order, member)
		if index < 0 {
			problems = append(problems, member+": required member is not in the header order")
			continue
		}
		offset, ok := offsets[member]
		if !ok {
			problems = append(problems, fmt.Sprintf("%s: not mapped (want slot %d)", member, headerSlot(index)))
			continue
		}
		seen[member] = true
		if want := headerSlot(index) * vtableSlot; offset != want {
			problems = append(problems, fmt.Sprintf("%s: offset %#x = slot %d, want slot %d",
				member, offset, offset/vtableSlot, headerSlot(index)))
		}
	}
	for member := range offsets {
		if !seen[member] {
			problems = append(problems, member+": mapped but not a required member of this interface")
		}
	}
	sort.Strings(problems)
	return problems
}

// The production INetwork struct must place every member it declares at the
// slot the header declares. Members the struct deliberately leaves unnamed are
// not part of the required set, but the numeric slots of the declared ones fix
// the gap exactly. This is the offset proof: it is separate from the behavioral
// proof in network_windows_inetwork_mapping_test.go.
func TestINetworkMemberSlotsMatchHeader(t *testing.T) {
	vtbl := (*iNetworkVtbl)(nil)
	offsets := map[string]uintptr{
		"get_Name":                   unsafe.Offsetof(vtbl.GetName),
		"get_NetworkId":              unsafe.Offsetof(vtbl.GetNetworkId),
		"get_DomainType":             unsafe.Offsetof(vtbl.GetDomainType),
		"get_NetworkConnections":     unsafe.Offsetof(vtbl.GetNetworkConnections),
		"GetTimeCreatedAndConnected": unsafe.Offsetof(vtbl.GetTimeCreatedAndConnected),
		"get_IsConnectedToInternet":  unsafe.Offsetof(vtbl.GetIsConnectedToInternet),
		"get_IsConnected":            unsafe.Offsetof(vtbl.GetIsConnected),
		"get_Connectivity":           unsafe.Offsetof(vtbl.GetConnectivity),
		"get_Category":               unsafe.Offsetof(vtbl.GetCategory),
	}
	if problems := checkMemberSlots(iNetworkHeaderOrder, iNetworkRequiredMembers, offsets); len(problems) != 0 {
		t.Fatalf("INetwork vtable does not match netlistmgr.h: %s", strings.Join(problems, "; "))
	}
	// The struct must end after get_Category (slot 18): a shorter struct
	// truncates the mapping, while a longer one means a member was added
	// without being accounted for here. put_Category (slot 19) is the one
	// trailing member outside this body's scope and must stay undeclared.
	categoryIndex := slices.Index(iNetworkHeaderOrder, "get_Category")
	if categoryIndex < 0 {
		t.Fatal("get_Category is not in the INetwork header order")
	}
	if got, want := unsafe.Sizeof(iNetworkVtbl{}), (headerSlot(categoryIndex)+1)*vtableSlot; got != want {
		t.Fatalf("sizeof(iNetworkVtbl) = %d bytes (%d slots), want %d bytes (through slot %d)",
			got, got/vtableSlot, want, headerSlot(categoryIndex))
	}
}

// rejectedINetworkVtbl is the layout shipped before the correction: the two
// VARIANT_BOOL getters were assumed to be the last interface members and the
// category was taken from get_DomainType. The permanent check must reject it,
// otherwise the slot assertion above would be vacuous.
type rejectedINetworkVtbl struct {
	comVtbl
	GetName                  uintptr // 7
	_                        [3]uintptr
	GetNetworkId             uintptr // 11
	GetCategory              uintptr // 12
	_                        [2]uintptr
	GetIsConnected           uintptr // 15
	GetIsConnectedToInternet uintptr // 16
}

// The check must name the three misread members and nothing else, so a future
// edit cannot quietly drop one of them from the table.
func TestINetworkSlotCheckRejectsShippedLayout(t *testing.T) {
	vtbl := (*rejectedINetworkVtbl)(nil)
	offsets := map[string]uintptr{
		"get_Name":      unsafe.Offsetof(vtbl.GetName),
		"get_NetworkId": unsafe.Offsetof(vtbl.GetNetworkId),
		// The shipped struct called slot 12 "GetCategory"; it is get_DomainType.
		"get_Category":              unsafe.Offsetof(vtbl.GetCategory),
		"get_IsConnected":           unsafe.Offsetof(vtbl.GetIsConnected),
		"get_IsConnectedToInternet": unsafe.Offsetof(vtbl.GetIsConnectedToInternet),
	}
	problems := checkMemberSlots(iNetworkHeaderOrder, iNetworkRequiredMembers, offsets)
	joined := strings.Join(problems, "\n")
	for _, want := range []string{
		"get_IsConnected: offset 0x78 = slot 15, want slot 16",
		"get_IsConnectedToInternet: offset 0x80 = slot 16, want slot 15",
		"get_Category: offset 0x60 = slot 12, want slot 18",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("slot check did not report %q; reported:\n%s", want, joined)
		}
	}
}

// The INetworkListManager prefix this body dispatches through is unchanged by
// the INetwork correction and is still asserted against its own header order.
// The two trailing VARIANT_BOOL getters are declared for a complete prefix
// (they are not called), so their slots are asserted too; get_Connectivity is
// not declared by this body and is therefore not required.
func TestNetworkListManagerCallSiteSlots(t *testing.T) {
	vtbl := (*iNetworkListManagerVtbl)(nil)
	offsets := map[string]uintptr{
		"GetNetworks":               unsafe.Offsetof(vtbl.GetNetworks),
		"GetNetwork":                unsafe.Offsetof(vtbl.GetNetwork),
		"GetNetworkConnections":     unsafe.Offsetof(vtbl.GetNetworkConnections),
		"GetNetworkConnection":      unsafe.Offsetof(vtbl.GetNetworkConnection),
		"get_IsConnectedToInternet": unsafe.Offsetof(vtbl.IsConnectedToInternet),
		"get_IsConnected":           unsafe.Offsetof(vtbl.IsConnected),
	}
	if problems := checkMemberSlots(iNetworkListManagerHeaderOrder, iNetworkListManagerRequiredMembers, offsets); len(problems) != 0 {
		t.Fatalf("INetworkListManager vtable does not match netlistmgr.h: %s", strings.Join(problems, "; "))
	}
	enumVtbl := (*iEnumNetworksVtbl)(nil)
	if offset, want := unsafe.Offsetof(enumVtbl.Next), 8*vtableSlot; offset != want {
		t.Fatalf("IEnumNetworks.Next vtable offset = %#x, want slot 8 (%#x)", offset, want)
	}
}

// withWirelessSeam installs a WLAN seam for one test and restores the
// production loader afterwards.
func withWirelessSeam(t *testing.T, query func() ([]WirelessNetwork, error)) {
	t.Helper()
	previous := wirelessQuery
	wirelessQuery = query
	t.Cleanup(func() { wirelessQuery = previous })
}

// The absent optional capability is a typed, ordinary error through MatchSSID
// and Snapshot; it never panics, and the NLM/adapter sections keep working.
func TestWirelessAbsentIsTypedCapabilityError(t *testing.T) {
	withWirelessSeam(t, func() ([]WirelessNetwork, error) {
		return nil, fmt.Errorf("%w: %w", errWirelessUnavailable, windows.ERROR_MOD_NOT_FOUND)
	})
	probe := windowsNetworkProbe{}
	matched, err := probe.MatchSSID(context.Background(), []string{"lab"})
	if matched {
		t.Fatal("MatchSSID matched an SSID without the WLAN capability")
	}
	if !errors.Is(err, errWirelessUnavailable) {
		t.Fatalf("MatchSSID error = %v, want a typed wireless capability error", err)
	}
	snapshot, snapshotErr := probe.Snapshot(context.Background())
	if !errors.Is(snapshotErr, errWirelessUnavailable) {
		t.Fatalf("Snapshot error = %v, want a typed wireless capability error", snapshotErr)
	}
	if len(snapshot.Wireless) != 0 {
		t.Fatalf("Snapshot reported %d wireless entries without the capability", len(snapshot.Wireless))
	}
	// The NLM and adapter sections do not depend on the WLAN capability: the
	// same call must have filled them (the assertion only requires that the
	// query did not abort before them, not a particular host state).
	if snapshot.QueriedAt.IsZero() {
		t.Fatal("Snapshot did not record a query time")
	}
}

// The present-capability seam control: an available WLAN capability still
// enumerates and matches, and the Snapshot carries it.
func TestWirelessPresentCapabilitySeamControl(t *testing.T) {
	withWirelessSeam(t, func() ([]WirelessNetwork, error) {
		return []WirelessNetwork{{InterfaceGUID: "guid", State: "connected", SSID: "lab"}}, nil
	})
	probe := windowsNetworkProbe{}
	matched, err := probe.MatchSSID(context.Background(), []string{"lab"})
	if err != nil || !matched {
		t.Fatalf("MatchSSID = %v,%v, want a match without an error", matched, err)
	}
	matched, err = probe.MatchSSID(context.Background(), []string{"other"})
	if err != nil || matched {
		t.Fatalf("MatchSSID(other) = %v,%v, want no match without an error", matched, err)
	}
	snapshot, snapshotErr := probe.Snapshot(context.Background())
	if snapshotErr != nil && !errors.Is(snapshotErr, errWirelessUnavailable) {
		t.Fatalf("Snapshot error = %v", snapshotErr)
	}
	if len(snapshot.Wireless) != 1 || snapshot.Wireless[0].SSID != "lab" {
		t.Fatalf("Snapshot wireless = %+v, want the seam value", snapshot.Wireless)
	}
}

// The real loader must never panic on a host without the optional capability:
// it either resolves every entry point or returns the typed capability error.
func TestLoadWLANResolvesOrReportsCapability(t *testing.T) {
	api, err := loadWLAN()
	if err != nil {
		if !errors.Is(err, errWirelessUnavailable) {
			t.Fatalf("loadWLAN error = %v, want a typed wireless capability error", err)
		}
		return
	}
	if api == nil || api.openHandle == nil || api.closeHandle == nil || api.enumInterfaces == nil || api.queryInterface == nil || api.freeMemory == nil {
		t.Fatalf("loadWLAN returned an incomplete API: %+v", api)
	}
}
