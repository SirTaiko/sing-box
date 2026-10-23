//go:build windows

package desync

// Behavioral regressions for the INetwork member mapping. The structural proof
// lives in network_windows_abi_test.go; this file drives the production call
// site (logicalNetworkState) against a COM-shaped object whose vtable entries
// are installed by netlistmgr.h slot number, so a wrong production offset reads
// a different member instead of the one it names.
//
// The guest that produced the earlier native PASS cannot discriminate the
// defect: its single network reports IsConnected == IsConnectedToInternet ==
// true and NLM_DOMAIN_TYPE_NON_DOMAIN_NETWORK (0) == NLM_NETWORK_CATEGORY_PUBLIC
// (0), so the shipped mapping and the corrected one return the same triple.
// These tests therefore supply the values the host could not: Connected and
// Internet disagree, and DomainType differs from Category.

import (
	"sort"
	"syscall"
	"testing"
	"unsafe"
)

// INetwork slots used by these fixtures (see iNetworkHeaderOrder for the
// provenance of the order and network_windows.go for the production layout).
const (
	iNetworkSlotDomainType            = 12
	iNetworkSlotIsConnectedToInternet = 15
	iNetworkSlotIsConnected           = 16
	iNetworkSlotCategory              = 18
	// The whole vtable through put_Category (slot 19). Unused slots answer
	// E_NOTIMPL so an unexpected call is visible instead of silently succeeding.
	iNetworkSlotCount = 20
)

const (
	variantFalse int16   = 0
	variantTrue  int16   = -1 // VARIANT_BOOL true is all bits set.
	eNotImpl     uintptr = 0x80004001
	ePointer     uintptr = 0x80004003
)

// NLM_DOMAIN_TYPE / NLM_NETWORK_CATEGORY values with different meanings, used to
// tell get_DomainType (slot 12) from get_Category (slot 18): domain type 3 is
// NLM_DOMAIN_TYPE_FORCED, which nlmCategoryName maps to "unknown", while
// category 1 is NLM_NETWORK_CATEGORY_PRIVATE, which it maps to "private".
const (
	fakeDomainTypeForced int32 = 3
	fakeCategoryPrivate  int32 = 1
)

// fakeINetworkValues is what one fake network reports through the ABI.
type fakeINetworkValues struct {
	connected  int16
	internet   int16
	domainType int32
	category   int32
}

// fakeINetwork is a layout-compatible INetwork: slots is a plain pointer table
// that the production struct is cast onto, and calls records which slots the
// production code actually dispatched through.
type fakeINetwork struct {
	network *iNetwork
	slots   []uintptr
	calls   []int
}

func newFakeINetwork(t *testing.T, values fakeINetworkValues) *fakeINetwork {
	t.Helper()
	fake := &fakeINetwork{slots: make([]uintptr, iNetworkSlotCount), calls: make([]int, 0, 8)}
	notImplemented := syscall.NewCallback(func(uintptr, uintptr) uintptr { return eNotImpl })
	for index := range fake.slots {
		fake.slots[index] = notImplemented
	}
	boolSlot := func(slot int, value int16) uintptr {
		return syscall.NewCallback(func(_ uintptr, out *int16) uintptr {
			if out == nil {
				return ePointer
			}
			fake.calls = append(fake.calls, slot)
			*out = value
			return 0
		})
	}
	enumSlot := func(slot int, value int32) uintptr {
		return syscall.NewCallback(func(_ uintptr, out *int32) uintptr {
			if out == nil {
				return ePointer
			}
			fake.calls = append(fake.calls, slot)
			*out = value
			return 0
		})
	}
	fake.slots[iNetworkSlotDomainType] = enumSlot(iNetworkSlotDomainType, values.domainType)
	fake.slots[iNetworkSlotIsConnectedToInternet] = boolSlot(iNetworkSlotIsConnectedToInternet, values.internet)
	fake.slots[iNetworkSlotIsConnected] = boolSlot(iNetworkSlotIsConnected, values.connected)
	fake.slots[iNetworkSlotCategory] = enumSlot(iNetworkSlotCategory, values.category)
	fake.network = &iNetwork{vtbl: (*iNetworkVtbl)(unsafe.Pointer(&fake.slots[0]))}
	return fake
}

// callSlot dispatches the typed member at one vtable slot through the same raw
// call path production uses, so the fixture is checked at the ABI boundary.
func (fake *fakeINetwork) callSlot(t *testing.T, slot int, out unsafe.Pointer) uint32 {
	t.Helper()
	return comCall(fake.slots[slot], unsafe.Pointer(fake.network), uintptr(out))
}

func (fake *fakeINetwork) readSlots() []int {
	slots := append([]int(nil), fake.calls...)
	sort.Ints(slots)
	return slots
}

// The production call site must read Connected from get_IsConnected (16),
// Internet from get_IsConnectedToInternet (15) and Category from get_Category
// (18). The shipped layout read 15/16/12 and returns a different triple here.
func TestLogicalNetworkStateUsesAuthoritativeINetworkMembers(t *testing.T) {
	fake := newFakeINetwork(t, fakeINetworkValues{
		connected:  variantTrue,
		internet:   variantFalse,
		domainType: fakeDomainTypeForced,
		category:   fakeCategoryPrivate,
	})
	state := logicalNetworkState(fake.network)
	if !state.Connected {
		t.Fatalf("Connected = false, want true from get_IsConnected (slot 16)")
	}
	if state.Internet {
		t.Fatalf("Internet = true, want false from get_IsConnectedToInternet (slot 15)")
	}
	if state.Category != "private" {
		t.Fatalf("Category = %q, want %q from get_Category (slot 18); get_DomainType(3) would report %q",
			state.Category, "private", nlmCategoryName(fakeDomainTypeForced))
	}
	if got, want := fake.readSlots(), []int{iNetworkSlotIsConnectedToInternet, iNetworkSlotIsConnected, iNetworkSlotCategory}; !equalInts(got, want) {
		t.Fatalf("production dispatched slots %v, want exactly %v", got, want)
	}
}

// The equal-values control: a host whose two state members agree and whose
// domain type equals its category cannot discriminate any candidate mapping by
// value — that is exactly why the earlier native PASS was a false green. The
// fixed implementation must still report such a host faithfully. The slots
// actually dispatched are asserted only by the distinct-value regression, so
// that this control stays value-only.
func TestLogicalNetworkStateEqualValuesControl(t *testing.T) {
	fake := newFakeINetwork(t, fakeINetworkValues{
		connected:  variantTrue,
		internet:   variantTrue,
		domainType: 0, // NLM_DOMAIN_TYPE_NON_DOMAIN_NETWORK
		category:   0, // NLM_NETWORK_CATEGORY_PUBLIC
	})
	state := logicalNetworkState(fake.network)
	if !state.Connected || !state.Internet || state.Category != "public" {
		t.Fatalf("state = %+v, want connected=true internet=true category=public", state)
	}
}

// The fixture itself must be ABI-faithful: each slot answers with the value of
// the member netlistmgr.h places there, independently of the production struct.
func TestFakeINetworkSlotsAreAuthoritative(t *testing.T) {
	fake := newFakeINetwork(t, fakeINetworkValues{
		connected:  variantTrue,
		internet:   variantFalse,
		domainType: fakeDomainTypeForced,
		category:   fakeCategoryPrivate,
	})
	var internet int16
	if hr := fake.callSlot(t, iNetworkSlotIsConnectedToInternet, unsafe.Pointer(&internet)); hr != 0 {
		t.Fatalf("slot %d call failed: %#x", iNetworkSlotIsConnectedToInternet, hr)
	}
	if internet != variantFalse {
		t.Fatalf("slot %d returned %d, want the internet value %d", iNetworkSlotIsConnectedToInternet, internet, variantFalse)
	}
	var connected int16
	if hr := fake.callSlot(t, iNetworkSlotIsConnected, unsafe.Pointer(&connected)); hr != 0 {
		t.Fatalf("slot %d call failed: %#x", iNetworkSlotIsConnected, hr)
	}
	if connected != variantTrue {
		t.Fatalf("slot %d returned %d, want the connected value %d", iNetworkSlotIsConnected, connected, variantTrue)
	}
	var domainType int32
	if hr := fake.callSlot(t, iNetworkSlotDomainType, unsafe.Pointer(&domainType)); hr != 0 {
		t.Fatalf("slot %d call failed: %#x", iNetworkSlotDomainType, hr)
	}
	if domainType != fakeDomainTypeForced {
		t.Fatalf("slot %d returned %d, want the domain type %d", iNetworkSlotDomainType, domainType, fakeDomainTypeForced)
	}
	var category int32
	if hr := fake.callSlot(t, iNetworkSlotCategory, unsafe.Pointer(&category)); hr != 0 {
		t.Fatalf("slot %d call failed: %#x", iNetworkSlotCategory, hr)
	}
	if category != fakeCategoryPrivate {
		t.Fatalf("slot %d returned %d, want the category %d", iNetworkSlotCategory, category, fakeCategoryPrivate)
	}
}

// Sensitivity control: the rejected layout (Connected <- 15, Internet <- 16,
// Category <- 12) reads a different triple from the very same object. This is
// what makes the behavioral regression above able to detect the shipped defect
// and the single-defect variants of it, on a host where the real values agree.
func TestShippedINetworkMappingReadsDifferentTriple(t *testing.T) {
	fake := newFakeINetwork(t, fakeINetworkValues{
		connected:  variantTrue,
		internet:   variantFalse,
		domainType: fakeDomainTypeForced,
		category:   fakeCategoryPrivate,
	})
	var shippedConnected int16 // the shipped struct read slot 15 for Connected
	if hr := fake.callSlot(t, iNetworkSlotIsConnectedToInternet, unsafe.Pointer(&shippedConnected)); hr != 0 {
		t.Fatalf("slot %d call failed: %#x", iNetworkSlotIsConnectedToInternet, hr)
	}
	var shippedInternet int16 // ... and slot 16 for Internet
	if hr := fake.callSlot(t, iNetworkSlotIsConnected, unsafe.Pointer(&shippedInternet)); hr != 0 {
		t.Fatalf("slot %d call failed: %#x", iNetworkSlotIsConnected, hr)
	}
	var shippedCategory int32 // ... and slot 12 for Category
	if hr := fake.callSlot(t, iNetworkSlotDomainType, unsafe.Pointer(&shippedCategory)); hr != 0 {
		t.Fatalf("slot %d call failed: %#x", iNetworkSlotDomainType, hr)
	}
	fixed := logicalNetworkState(fake.network)
	if shippedConnected != 0 || shippedInternet == 0 || nlmCategoryName(shippedCategory) != "unknown" {
		t.Fatalf("fixture is not discriminating: shipped mapping reads connected=%d internet=%d category=%q",
			shippedConnected, shippedInternet, nlmCategoryName(shippedCategory))
	}
	if fixed.Connected == (shippedConnected != 0) || fixed.Internet == (shippedInternet != 0) || fixed.Category == nlmCategoryName(shippedCategory) {
		t.Fatalf("fixed mapping %+v is indistinguishable from the shipped reads connected=%v internet=%v category=%q",
			fixed, shippedConnected != 0, shippedInternet != 0, nlmCategoryName(shippedCategory))
	}
}

func equalInts(left, right []int) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
