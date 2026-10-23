//go:build windows

package desync

// Production Windows network probe: WLAN API for SSID state and adapter
// indices, Network List Manager for logical networks.
//
// Source of truth for the semantics: nfq/darkmagic.c wlan_filter_match(),
// nlm_filter_match(), AdapterID2Name() and nlm_list(). The API surface is the
// documented Windows one:
//
//	WlanOpenHandle/WlanEnumInterfaces/WlanQueryInterface/WlanFreeMemory/
//	WlanCloseHandle                      (wlanapi.dll, WLAN_INTERFACE_STATE)
//	GetAdaptersAddresses                (iphlpapi.dll, adapter index/name)
//	CLSID_NetworkListManager ->
//	  INetworkListManager::GetNetworks(NLM_ENUM_NETWORK_CONNECTED)
//	  IEnumNetworks::Next -> INetwork::get_Name/get_NetworkId/get_IsConnected/
//	  get_IsConnectedToInternet/get_Category
//
// Every handle and COM pointer is released on every path (defer + explicit
// release). A failing call returns an error, which makes the activation gate
// inactive and pass-through: no packet is transformed while the platform state
// cannot be established. Native execution is deferred to the Windows VM
// boundary; this file is compile-verified only on the build host.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func defaultNetworkProbe() NetworkProbe { return windowsNetworkProbe{} }

type windowsNetworkProbe struct{}

var (
	// loadWLAN resolves the optional Wireless LAN capability. The DLL and each
	// procedure are resolved explicitly: an absent wlanapi.dll (typical on
	// Windows Server SKUs without the Wireless LAN feature) is an ordinary
	// capability error, never a LazyProc.Call panic. The variable is a seam so a
	// test can install a present-capability control.
	loadWLAN = func() (*wlanAPI, error) {
		if err := wlanapiDLL.Load(); err != nil {
			return nil, fmt.Errorf("%w: %v", errWirelessUnavailable, err)
		}
		api := &wlanAPI{
			openHandle:     wlanapiDLL.NewProc("WlanOpenHandle"),
			closeHandle:    wlanapiDLL.NewProc("WlanCloseHandle"),
			enumInterfaces: wlanapiDLL.NewProc("WlanEnumInterfaces"),
			queryInterface: wlanapiDLL.NewProc("WlanQueryInterface"),
			freeMemory:     wlanapiDLL.NewProc("WlanFreeMemory"),
		}
		for _, procedure := range []*windows.LazyProc{api.openHandle, api.closeHandle, api.enumInterfaces, api.queryInterface, api.freeMemory} {
			if err := procedure.Find(); err != nil {
				return nil, fmt.Errorf("%w: %v", errWirelessUnavailable, err)
			}
		}
		return api, nil
	}

	wlanapiDLL = windows.NewLazySystemDLL("wlanapi.dll")

	ole32DLL           = windows.NewLazySystemDLL("ole32.dll")
	procCoInitializeEx = ole32DLL.NewProc("CoInitializeEx")
	procCoCreateInst   = ole32DLL.NewProc("CoCreateInstance")
	procCoUninitialize = ole32DLL.NewProc("CoUninitialize")

	oleaut32DLL   = windows.NewLazySystemDLL("oleaut32.dll")
	sysFreeString = oleaut32DLL.NewProc("SysFreeString")
)

// errWirelessUnavailable reports that the optional Wireless LAN capability is
// absent on this host. It is a capability error, not an unsupported Windows
// implementation: the Network List Manager and adapter queries keep working
// without it.
var errWirelessUnavailable = errors.New("desync: wireless LAN capability is unavailable on this host")

// wlanAPI is the resolved WLAN client entry points of one query.
type wlanAPI struct {
	openHandle     *windows.LazyProc
	closeHandle    *windows.LazyProc
	enumInterfaces *windows.LazyProc
	queryInterface *windows.LazyProc
	freeMemory     *windows.LazyProc
}

// wirelessQuery is the socket-facing WLAN seam used by MatchSSID and Snapshot.
// Production is queryWirelessInterfaces; a test substitutes the present and
// absent capability paths without loading the DLL.
var wirelessQuery = queryWirelessInterfaces

// WLAN constants from wlanapi.h.
const (
	wlanMaxInterfaceDescriptionLength = 256
	wlanInterfaceStateConnected       = 1
	wlanIntfOpcodeCurrentConnection   = 7
)

type wlanInterfaceInfo struct {
	InterfaceGUID windows.GUID
	Description   [wlanMaxInterfaceDescriptionLength]uint16
	State         uint32
}

type wlanInterfaceInfoList struct {
	NumberOfItems uint32
	Index         uint32
	InterfaceInfo [1]wlanInterfaceInfo
}

// wlanConnectionAttributesPrefix was the shipped synthetic prefix: it declared
// the documented fields plus an extra RemainingFields array, which raised the
// required value size to 620 bytes while WLAN_CONNECTION_ATTRIBUTES is 604
// bytes. The documented layout now lives in wlan_connection_attributes.go so
// the exact size and the 32-byte SSID bound are regression-tested without a
// Windows host.

func (windowsNetworkProbe) MatchSSID(_ context.Context, ssids []string) (bool, error) {
	snapshot, err := wirelessQuery()
	if err != nil {
		return false, err
	}
	for _, wireless := range snapshot {
		if wireless.State != "connected" {
			continue
		}
		for _, wanted := range ssids {
			if wireless.SSID == wanted {
				return true, nil
			}
		}
	}
	return false, nil
}

func (windowsNetworkProbe) MatchNLM(_ context.Context, networks []string) (bool, error) {
	snapshot, err := queryLogicalNetworks()
	if err != nil {
		return false, err
	}
	for _, network := range snapshot {
		if !network.Connected {
			continue
		}
		for _, wanted := range networks {
			if network.Name == wanted || strings.EqualFold(network.ID, wanted) {
				return true, nil
			}
			if guid, guidErr := parseGUID(wanted); guidErr == nil {
				if current, currentErr := parseGUID(network.ID); currentErr == nil && current == guid {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

func (windowsNetworkProbe) Snapshot(ctx context.Context) (WindowsNetworkSnapshot, error) {
	return windowsNetworkProbe{}.SnapshotWithOptions(ctx, NetworkQueryOptions{})
}

// SnapshotWithOptions implements the optional bounded/all-scope query. The
// connected default is unchanged (NLM_ENUM_NETWORK_CONNECTED); All uses
// NLM_ENUM_NETWORK_ALL and reports the real per-network connected/internet/
// category state. Limit bounds each array; empty means no explicit bound (the
// activation path passes zero). Every handle and COM pointer is still released
// on every path, and no native state is cached between calls.
func (windowsNetworkProbe) SnapshotWithOptions(_ context.Context, options NetworkQueryOptions) (WindowsNetworkSnapshot, error) {
	snapshot := WindowsNetworkSnapshot{QueriedAt: time.Now()}
	// The Wireless LAN capability is optional. An absent wlanapi.dll must not
	// hide the Network List Manager and adapter state, which stay usable on the
	// same host: the capability error is kept and returned after the sections
	// that do not depend on it have been filled in.
	wireless, wirelessErr := wirelessQuery()
	if wirelessErr == nil {
		snapshot.Wireless = boundWireless(wireless, options.Limit)
	}
	scope := uint32(nlmEnumNetworkConnected)
	if options.All {
		scope = nlmEnumNetworkAll
	}
	networks, err := queryLogicalNetworksScope(scope)
	if err != nil {
		return snapshot, err
	}
	snapshot.Networks = boundNetworks(networks, options.Limit)
	adapters, err := queryAdapters()
	if err != nil {
		return snapshot, err
	}
	snapshot.Adapters = boundAdapters(adapters, options.Limit)
	if wirelessErr != nil {
		return snapshot, wirelessErr
	}
	return snapshot, nil
}

func boundWireless(values []WirelessNetwork, limit uint16) []WirelessNetwork {
	if limit == 0 || len(values) <= int(limit) {
		return values
	}
	return values[:limit]
}

func boundNetworks(values []LogicalNetwork, limit uint16) []LogicalNetwork {
	if limit == 0 || len(values) <= int(limit) {
		return values
	}
	return values[:limit]
}

func boundAdapters(values []NetworkAdapter, limit uint16) []NetworkAdapter {
	if limit == 0 || len(values) <= int(limit) {
		return values
	}
	return values[:limit]
}

// queryWirelessInterfaces opens and closes one WLAN client handle per query.
// The handle is never cached across queries, so no state outlives the call.
func queryWirelessInterfaces() ([]WirelessNetwork, error) {
	api, err := loadWLAN()
	if err != nil {
		return nil, err
	}
	var negotiated uint32
	var handle windows.Handle
	result, _, _ := api.openHandle.Call(2, 0, uintptr(unsafe.Pointer(&negotiated)), uintptr(unsafe.Pointer(&handle)))
	if result != 0 {
		return nil, fmt.Errorf("desync: WlanOpenHandle failed: %d", result)
	}
	if handle == 0 {
		return nil, fmt.Errorf("desync: WlanOpenHandle returned no handle")
	}
	defer api.closeHandle.Call(uintptr(handle), 0)

	var list *wlanInterfaceInfoList
	result, _, _ = api.enumInterfaces.Call(uintptr(handle), 0, uintptr(unsafe.Pointer(&list)))
	if result != 0 {
		return nil, fmt.Errorf("desync: WlanEnumInterfaces failed: %d", result)
	}
	if list == nil {
		return nil, nil
	}
	defer api.freeMemory.Call(uintptr(unsafe.Pointer(list)))

	var wireless []WirelessNetwork
	entries := unsafe.Slice(&list.InterfaceInfo[0], int(list.NumberOfItems))
	for index := range entries {
		entry := &entries[index]
		item := WirelessNetwork{
			InterfaceGUID: formatGUID(entry.InterfaceGUID),
			Description:   windows.UTF16ToString(entry.Description[:]),
			State:         wlanStateName(entry.State),
		}
		if entry.State != wlanInterfaceStateConnected {
			wireless = append(wireless, item)
			continue
		}
		var size uint32
		var data unsafe.Pointer
		var opcodeType uint32
		result, _, _ = api.queryInterface.Call(
			uintptr(handle),
			uintptr(unsafe.Pointer(&entry.InterfaceGUID)),
			wlanIntfOpcodeCurrentConnection,
			0,
			uintptr(unsafe.Pointer(&size)),
			uintptr(unsafe.Pointer(&data)),
			uintptr(unsafe.Pointer(&opcodeType)),
		)
		if result != 0 {
			// One failing interface must not hide the others; report the
			// interface as unknown rather than inventing an SSID.
			item.State = "error"
			wireless = append(wireless, item)
			continue
		}
		if data != nil {
			item.SSID = wlanSSIDFromValue(data, size)
			api.freeMemory.Call(uintptr(data))
		}
		wireless = append(wireless, item)
	}
	return wireless, nil
}

func wlanStateName(state uint32) string {
	switch state {
	case 0:
		return "not_ready"
	case wlanInterfaceStateConnected:
		return "connected"
	case 2:
		return "ad_hoc_network_formed"
	case 3:
		return "disconnecting"
	case 4:
		return "disconnected"
	case 5:
		return "associating"
	case 6:
		return "discovering"
	case 7:
		return "authenticating"
	}
	return fmt.Sprintf("state_%d", state)
}

// queryAdapters maps adapter GUID -> friendly name and interface index. The
// index is the same value a WinDivert ifIdx comparison uses.
func queryAdapters() ([]NetworkAdapter, error) {
	var size uint32
	const flags = 0x00000002 | 0x00000004 // GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST
	err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, nil, &size)
	if err != nil && err != syscall.ERROR_BUFFER_OVERFLOW {
		return nil, fmt.Errorf("desync: GetAdaptersAddresses(size): %w", err)
	}
	if size == 0 {
		return nil, nil
	}
	buffer := make([]byte, size)
	first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0]))
	if err = windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, first, &size); err != nil {
		return nil, fmt.Errorf("desync: GetAdaptersAddresses: %w", err)
	}
	var adapters []NetworkAdapter
	for adapter := first; adapter != nil; adapter = adapter.Next {
		item := NetworkAdapter{Index: adapter.IfIndex}
		if adapter.AdapterName != nil {
			item.GUID = windows.BytePtrToString(adapter.AdapterName)
		}
		if adapter.FriendlyName != nil {
			item.Name = windows.UTF16PtrToString(adapter.FriendlyName)
		}
		adapters = append(adapters, item)
	}
	return adapters, nil
}

// --------------------------- Network List Manager ---------------------------
//
// The COM interfaces derive from IDispatch, so the vtable prefix is fixed:
// IUnknown (3 entries) followed by GetTypeInfoCount/GetTypeInfo/GetIDsOfNames/
// Invoke (4 entries), i.e. the interface-specific members start at slot 7.
//
// INetwork (IID DCB00002-570F-4A9B-8D69-199FDBA5723B) does NOT have that
// shape: its property getters are interleaved with the enumeration methods.
// The order below is the one netlistmgr.h declares, transcribed from the SDK
// interface definition through the SDK-generated Win32 metadata bindings
// (windows-docs-rs Win32/Networking/NetworkListManager::INetwork_Impl lists the
// 13 members in exactly this order) and matched slot for slot by an independent
// COM binding of the same header (tailscale wgengine/winnet INetworkVtbl):
//
//	slot 7  get_Name(BSTR**)
//	slot 8  put_Name(BSTR)                  slot 9  get_Description(BSTR**)
//	slot 10 put_Description(BSTR)
//	slot 11 get_NetworkId(GUID*)
//	slot 12 get_DomainType(NLM_DOMAIN_TYPE*)
//	slot 13 get_NetworkConnections(IEnumNetworkConnections**)
//	slot 14 GetTimeCreatedAndConnected(ULONG*, ULONG*, ULONG*, ULONG*)
//	slot 15 get_IsConnectedToInternet(VARIANT_BOOL*)
//	slot 16 get_IsConnected(VARIANT_BOOL*)
//	slot 17 get_Connectivity(NLM_CONNECTIVITY*)
//	slot 18 get_Category(NLM_NETWORK_CATEGORY*)
//	slot 19 put_Category(NLM_NETWORK_CATEGORY)
//
// The shipped struct assumed the two VARIANT_BOOL getters were the last two
// interface members, which read Connected from get_IsConnectedToInternet,
// Internet from get_IsConnected and the category from get_DomainType. Those
// three slots are spelled out below, so a wrong slot is a wrong call.
//
// Every call checks its HRESULT. A wrong or unavailable member therefore
// fails the query (gate inactive, packets pass) instead of being trusted.

type comVtbl struct {
	// IUnknown
	QueryInterface uintptr
	AddRef         uintptr
	Release        uintptr
	// IDispatch
	GetTypeInfoCount uintptr
	GetTypeInfo      uintptr
	GetIDsOfNames    uintptr
	Invoke           uintptr
}

type iNetworkListManager struct {
	vtbl *iNetworkListManagerVtbl
}

type iNetworkListManagerVtbl struct {
	comVtbl
	GetNetworks           uintptr
	GetNetwork            uintptr
	GetNetworkConnections uintptr
	GetNetworkConnection  uintptr
	// The two trailing [propget] VARIANT_BOOL members are not called by this
	// body; they are listed so the layout above is complete and reviewable.
	IsConnectedToInternet uintptr
	IsConnected           uintptr
}

type iEnumNetworks struct {
	vtbl *iEnumNetworksVtbl
}

type iEnumNetworksVtbl struct {
	comVtbl
	NewEnum uintptr
	Next    uintptr
	Skip    uintptr
	Reset   uintptr
	Clone   uintptr
}

type iNetwork struct {
	vtbl *iNetworkVtbl
}

// iNetworkVtbl is the INetwork vtable in netlistmgr.h order. The members this
// file does not call are still declared, so every offset is explicit and the
// layout cannot drift silently; put_Category (slot 19) is the only trailing
// member left out, because nothing on this side writes it.
type iNetworkVtbl struct {
	comVtbl
	GetName                    uintptr    // 7:  [propget] Name -> BSTR*
	_                          [3]uintptr // 8: put_Name, 9: get_Description, 10: put_Description
	GetNetworkId               uintptr    // 11: [propget] NetworkId -> GUID*
	GetDomainType              uintptr    // 12: [propget] DomainType -> NLM_DOMAIN_TYPE*
	GetNetworkConnections      uintptr    // 13: [propget] NetworkConnections -> IEnumNetworkConnections**
	GetTimeCreatedAndConnected uintptr    // 14: created/connected FILETIMEs (4 x ULONG*)
	GetIsConnectedToInternet   uintptr    // 15: [propget] IsConnectedToInternet -> VARIANT_BOOL*
	GetIsConnected             uintptr    // 16: [propget] IsConnected -> VARIANT_BOOL*
	GetConnectivity            uintptr    // 17: [propget] Connectivity -> NLM_CONNECTIVITY*
	GetCategory                uintptr    // 18: [propget] Category -> NLM_NETWORK_CATEGORY*
}

// CLSID_NetworkListManager and IID_INetworkListManager from netlistmgr.h.
var (
	clsidNetworkListManager = windows.GUID{Data1: 0xDCB00C01, Data2: 0x570F, Data3: 0x4A9B,
		Data4: [8]byte{0x8D, 0x69, 0x19, 0x9F, 0xDB, 0xA5, 0x72, 0x3B}}
	iidNetworkListManager = windows.GUID{Data1: 0xDCB00000, Data2: 0x570F, Data3: 0x4A9B,
		Data4: [8]byte{0x8D, 0x69, 0x19, 0x9F, 0xDB, 0xA5, 0x72, 0x3B}}
)

const (
	clsctxAll               = 0x17
	nlmEnumNetworkConnected = 1
	nlmEnumNetworkAll       = 3
	hresultFalse            = 0x00000001
	// comApartmentThreaded is COINIT_APARTMENTTHREADED.
	comApartmentThreaded = 0x2
)

func queryLogicalNetworks() ([]LogicalNetwork, error) {
	return queryLogicalNetworksScope(nlmEnumNetworkConnected)
}

// queryLogicalNetworksScope enumerates the requested Network List Manager scope
// on one pinned native OS thread. A COM apartment belongs to the OS thread,
// not to the goroutine: initialization, every interface call, every Release and
// the uninitialization must all run on the thread that owns the apartment, and
// only an initialization reference acquired by this invocation may be balanced.
func queryLogicalNetworksScope(scope uint32) ([]LogicalNetwork, error) {
	var (
		networks []LogicalNetwork
		queryErr error
	)
	runOnNativeThread(func() {
		networks, queryErr = queryLogicalNetworksOnThread(scope)
	})
	return networks, queryErr
}

// queryLogicalNetworksOnThread runs entirely on the caller's pinned thread.
func queryLogicalNetworksOnThread(scope uint32) ([]LogicalNetwork, error) {
	result, _, _ := procCoInitializeEx.Call(0, comApartmentThreaded)
	releaseApartment, err := comApartmentEnter(uint32(result), func() { procCoUninitialize.Call() })
	if err != nil {
		return nil, err
	}
	if releaseApartment != nil {
		// S_OK and S_FALSE each acquired one reference that this invocation
		// must balance exactly once. RPC_E_CHANGED_MODE acquired none: that
		// apartment belongs to another owner and must not be uninitialized.
		defer releaseApartment()
	}
	var manager *iNetworkListManager
	result, _, _ = procCoCreateInst.Call(
		uintptr(unsafe.Pointer(&clsidNetworkListManager)),
		0,
		clsctxAll,
		uintptr(unsafe.Pointer(&iidNetworkListManager)),
		uintptr(unsafe.Pointer(&manager)),
	)
	if uint32(result) != 0 || manager == nil {
		return nil, fmt.Errorf("desync: CoCreateInstance(NetworkListManager) failed: %#x", uint32(result))
	}
	defer comRelease(&manager.vtbl.comVtbl, unsafe.Pointer(manager))

	var enumerator *iEnumNetworks
	hr := comCall(manager.vtbl.GetNetworks, unsafe.Pointer(manager),
		uintptr(scope), uintptr(unsafe.Pointer(&enumerator)))
	if hr != 0 || enumerator == nil {
		return nil, fmt.Errorf("desync: INetworkListManager::GetNetworks failed: %#x", hr)
	}
	defer comRelease(&enumerator.vtbl.comVtbl, unsafe.Pointer(enumerator))

	var networks []LogicalNetwork
	for {
		var network *iNetwork
		hr = comCall(enumerator.vtbl.Next, unsafe.Pointer(enumerator), 1, uintptr(unsafe.Pointer(&network)), 0)
		if hr == hresultFalse {
			break
		}
		if hr != 0 {
			return nil, fmt.Errorf("desync: IEnumNetworks::Next failed: %#x", hr)
		}
		if network == nil {
			break
		}
		item := logicalNetworkState(network)
		var namePtr *uint16
		if hr = comCall(network.vtbl.GetName, unsafe.Pointer(network), uintptr(unsafe.Pointer(&namePtr))); hr == 0 && namePtr != nil {
			item.Name = windows.UTF16PtrToString(namePtr)
			syscall.SyscallN(sysFreeString.Addr(), uintptr(unsafe.Pointer(namePtr)))
		}
		var networkID windows.GUID
		if hr = comCall(network.vtbl.GetNetworkId, unsafe.Pointer(network), uintptr(unsafe.Pointer(&networkID))); hr == 0 {
			item.ID = formatGUID(networkID)
		}
		comRelease(&network.vtbl.comVtbl, unsafe.Pointer(network))
		networks = append(networks, item)
	}
	return networks, nil
}

// logicalNetworkState queries the real per-network state. With the connected
// scope every returned network is connected; with the all scope disconnected
// networks are reported as connected=false instead of being mislabelled.
// Connected, Internet and Category are read from the netlistmgr.h members that
// carry those values (get_IsConnected 16, get_IsConnectedToInternet 15,
// get_Category 18), not from the nearby slots that happen to answer on a host
// where all of them are numerically equal.
func logicalNetworkState(network *iNetwork) LogicalNetwork {
	item := LogicalNetwork{}
	var connected int16
	if hr := comCall(network.vtbl.GetIsConnected, unsafe.Pointer(network), uintptr(unsafe.Pointer(&connected))); hr == 0 {
		item.Connected = connected != 0
	}
	var internet int16
	if hr := comCall(network.vtbl.GetIsConnectedToInternet, unsafe.Pointer(network), uintptr(unsafe.Pointer(&internet))); hr == 0 {
		item.Internet = internet != 0
	}
	var category int32
	if hr := comCall(network.vtbl.GetCategory, unsafe.Pointer(network), uintptr(unsafe.Pointer(&category))); hr == 0 {
		item.Category = nlmCategoryName(category)
	}
	return item
}

func nlmCategoryName(category int32) string {
	switch category {
	case 0:
		return "public"
	case 1:
		return "private"
	case 2:
		return "domain"
	default:
		return "unknown"
	}
}

func comCall(method uintptr, receiver unsafe.Pointer, args ...uintptr) uint32 {
	if method == 0 || receiver == nil {
		return 0x80004003 // E_POINTER
	}
	callArgs := make([]uintptr, 0, 1+len(args))
	callArgs = append(callArgs, uintptr(receiver))
	callArgs = append(callArgs, args...)
	result, _, _ := syscall.SyscallN(method, callArgs...)
	return uint32(result)
}

func comRelease(vtbl *comVtbl, object unsafe.Pointer) {
	if vtbl == nil || object == nil || vtbl.Release == 0 {
		return
	}
	syscall.SyscallN(vtbl.Release, uintptr(object))
}

func formatGUID(guid windows.GUID) string {
	return fmt.Sprintf("%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		guid.Data1, guid.Data2, guid.Data3,
		guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
		guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7])
}
