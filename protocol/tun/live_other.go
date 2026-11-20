//go:build !linux && !windows

package tun

import (
	tun "github.com/sagernet/sing-tun"
	"os"
)

func setDesktopMTU(string, uint32) error { return os.ErrInvalid }

func updateDesktopRoutes(device tun.Tun, _, next tun.Options) error {
	return device.UpdateRouteOptions(next)
}
