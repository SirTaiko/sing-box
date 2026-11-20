package tun

import (
	"github.com/sagernet/netlink"
	tun "github.com/sagernet/sing-tun"
)

func setDesktopMTU(name string, mtu uint32) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	return netlink.LinkSetMTU(link, int(mtu))
}

func updateDesktopRoutes(device tun.Tun, _, next tun.Options) error {
	if d, ok := device.(desktopRouteUpdater); ok {
		return d.UpdateDesktopRouteOptions(next)
	}
	return device.UpdateRouteOptions(next)
}
