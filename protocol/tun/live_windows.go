package tun

import (
	"errors"
	"fmt"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/windnsapi"
	"net"
	"net/netip"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var ipHelper = windows.NewLazySystemDLL("iphlpapi.dll")
var setIPInterfaceEntry = ipHelper.NewProc("SetIpInterfaceEntry")
var initializeRoute = ipHelper.NewProc("InitializeIpForwardEntry")
var createRoute = ipHelper.NewProc("CreateIpForwardEntry2")
var deleteRoute = ipHelper.NewProc("DeleteIpForwardEntry2")

func setDesktopMTU(name string, mtu uint32) error {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return err
	}
	row := windows.MibIpInterfaceRow{Family: windows.AF_INET, InterfaceIndex: uint32(iface.Index)}
	if err = windows.GetIpInterfaceEntry(&row); err != nil {
		return err
	}
	row.NlMtu = mtu
	row.SitePrefixLength = 0
	result, _, _ := setIPInterfaceEntry.Call(uintptr(unsafe.Pointer(&row)))
	if result != 0 {
		return syscall.Errno(result)
	}
	return nil
}

// Reconcile only the prefixes owned by this TUN. FlushRoutes would also
// remove the on-link route that makes Wintun's next hop reachable.
func updateDesktopRoutes(device tun.Tun, before, after tun.Options) error {
	if !after.AutoRoute || after.EXP_ExternalConfiguration {
		return nil
	}
	native, ok := device.(interface{ LUID() uint64 })
	if !ok {
		return errors.New("missing Windows TUN LUID")
	}
	old, err := before.BuildAutoRouteRanges(false)
	if err != nil {
		return err
	}
	next, err := after.BuildAutoRouteRanges(false)
	if err != nil {
		return err
	}
	oldSet := make(map[netip.Prefix]bool, len(old))
	newSet := make(map[netip.Prefix]bool, len(next))
	for _, p := range old {
		oldSet[p] = true
	}
	for _, p := range next {
		newSet[p] = true
	}
	update := func(prefix netip.Prefix, opts tun.Options, add bool) error {
		var row windows.MibIpForwardRow2
		initializeRoute.Call(uintptr(unsafe.Pointer(&row)))
		row.InterfaceLuid = native.LUID()
		row.Metric = 0
		setAddr := func(s *windows.RawSockaddrInet, addr netip.Addr) {
			if addr.Is4() {
				ip := (*windows.RawSockaddrInet4)(unsafe.Pointer(s))
				ip.Family = windows.AF_INET
				ip.Addr = addr.As4()
			} else {
				ip := (*windows.RawSockaddrInet6)(unsafe.Pointer(s))
				ip.Family = windows.AF_INET6
				ip.Addr = addr.As16()
			}
		}
		setAddr(&row.DestinationPrefix.Prefix, prefix.Addr())
		row.DestinationPrefix.PrefixLength = uint8(prefix.Bits())
		if prefix.Addr().Is4() {
			setAddr(&row.NextHop, opts.Inet4GatewayAddr())
		} else {
			setAddr(&row.NextHop, opts.Inet6GatewayAddr())
		}
		op := deleteRoute
		if add {
			op = createRoute
		}
		ret, _, _ := op.Call(uintptr(unsafe.Pointer(&row)))
		code := syscall.Errno(ret)
		if ret == 0 || add && code == windows.ERROR_OBJECT_ALREADY_EXISTS || !add && code == windows.ERROR_NOT_FOUND {
			return nil
		}
		return fmt.Errorf("update TUN route %s: %w", prefix, code)
	}
	for _, p := range next {
		if !oldSet[p] {
			if err = update(p, after, true); err != nil {
				return err
			}
		}
	}
	for _, p := range old {
		if !newSet[p] {
			if err = update(p, before, false); err != nil {
				return err
			}
		}
	}
	return windnsapi.FlushResolverCache()
}
