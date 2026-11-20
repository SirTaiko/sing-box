package tun

import (
	"errors"
	"slices"

	"github.com/sagernet/sing-box/option"
	tun "github.com/sagernet/sing-tun"
)

type desktopRouteUpdater interface{ UpdateDesktopRouteOptions(tun.Options) error }

func (t *Inbound) CanSwitchRedirect() bool { _, ok := t.tunIf.(desktopRouteUpdater); return ok }

func (t *Inbound) UpdateDesktopOptions(before, after *option.TunInboundOptions) error {
	if t.tunIf == nil {
		return errors.New("TUN is not running")
	}
	name, err := t.tunIf.Name()
	if err != nil {
		return err
	}
	makeOptions := func(o *option.TunInboundOptions) tun.Options {
		opts := t.tunOptions
		opts.Name = name
		opts.MTU = o.MTU
		opts.AutoRedirectMarkMode = o.AutoRedirect
		opts.Inet4RouteExcludeAddress = nil
		opts.Inet6RouteExcludeAddress = nil
		for _, prefix := range o.RouteExcludeAddress {
			if prefix.Addr().Is4() {
				opts.Inet4RouteExcludeAddress = append(opts.Inet4RouteExcludeAddress, prefix)
			} else {
				opts.Inet6RouteExcludeAddress = append(opts.Inet6RouteExcludeAddress, prefix)
			}
		}
		return opts
	}
	refreshRoutes := before.AutoRedirect != after.AutoRedirect || !slices.Equal(before.RouteExcludeAddress, after.RouteExcludeAddress)
	if refreshRoutes {
		prev, next := makeOptions(before), makeOptions(after)
		set := func(from, opts tun.Options) error {
			if t.autoRedirect != nil {
				old := t.autoRedirect
				t.autoRedirect = nil
				if err := old.Close(); err != nil {
					return err
				}
			}
			if owner, ok := t.networkManager.(interface{ UnregisterAutoRedirectOutputMark(uint32) }); ok {
				if t.ownsRedirectMark {
					owner.UnregisterAutoRedirectOutputMark(t.tunOptions.AutoRedirectOutputMark)
					t.ownsRedirectMark = false
				}
			}
			if err := updateDesktopRoutes(t.tunIf, from, opts); err != nil {
				return err
			}

			if opts.AutoRedirectMarkMode {
				if err := t.networkManager.RegisterAutoRedirectOutputMark(opts.AutoRedirectOutputMark); err != nil {
					return err
				}
				t.ownsRedirectMark = true
				redirect, err := t.newRedirect(&opts)
				if err != nil {
					return err
				}
				t.autoRedirect = redirect
				if err = redirect.Start(); err != nil {
					return err
				}
			}
			return nil
		}
		if err = set(prev, next); err != nil {
			return errors.Join(err, set(next, prev))
		}
	}
	if before.MTU != after.MTU {
		if err = setDesktopMTU(name, after.MTU); err != nil {
			if refreshRoutes {
				restore := *before
				restore.MTU = after.MTU
				return errors.Join(err, t.UpdateDesktopOptions(after, &restore))
			}
			return err
		}
	}
	return nil
}
