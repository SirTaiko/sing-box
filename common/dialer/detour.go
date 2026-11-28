package dialer

import (
	"context"
	"net"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type DirectDialer interface {
	IsEmpty() bool
}

type DetourDialer struct {
	lookup                  func() (adapter.Outbound, bool)
	detour                  string
	defaultOutbound         bool
	disableEmptyDirectCheck bool
	dialer                  N.Dialer
	initOnce                sync.Once
	initErr                 error
}

func NewDetour(outboundManager adapter.OutboundManager, detour string, disableEmptyDirectCheck bool) N.Dialer {
	return &DetourDialer{lookup: bindDetour(outboundManager, detour), detour: detour, disableEmptyDirectCheck: disableEmptyDirectCheck}
}

func NewDefaultOutboundDetour(outboundManager adapter.OutboundManager) N.Dialer {
	return &DetourDialer{lookup: bindDetour(outboundManager, ""), defaultOutbound: true}
}

func bindDetour(manager adapter.OutboundManager, tag string) func() (adapter.Outbound, bool) {
	if binder, ok := manager.(interface {
		BindOutbound(string) func() (adapter.Outbound, bool)
	}); ok {
		return binder.BindOutbound(tag)
	}
	if tag != "" {
		return func() (adapter.Outbound, bool) { return manager.Outbound(tag) }
	}
	return func() (adapter.Outbound, bool) { ob := manager.Default(); return ob, ob != nil }
}

func InitializeDetour(dialer N.Dialer) error {
	detourDialer, isDetour := common.Cast[*DetourDialer](dialer)
	if !isDetour {
		return nil
	}
	return common.Error(detourDialer.Dialer())
}

func (d *DetourDialer) Dialer() (N.Dialer, error) {
	d.initOnce.Do(d.init)
	return d.dialer, d.initErr
}

func (d *DetourDialer) init() {
	dialer, found := d.lookup()
	if !found {
		d.initErr = E.New("outbound detour not found: ", d.detour)
		return
	}
	if !d.defaultOutbound && !d.disableEmptyDirectCheck {
		if directDialer, isDirect := dialer.(DirectDialer); isDirect {
			if directDialer.IsEmpty() {
				d.initErr = E.New("detour to an empty direct outbound makes no sense")
				return
			}
		}
	}
	d.dialer = dialer
}

func (d *DetourDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	dialer, err := d.Dialer()
	if err != nil {
		return nil, err
	}
	return dialer.DialContext(ctx, network, destination)
}

func (d *DetourDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	dialer, err := d.Dialer()
	if err != nil {
		return nil, err
	}
	return dialer.ListenPacket(ctx, destination)
}

func (d *DetourDialer) Upstream() any {
	detour, _ := d.Dialer()
	return detour
}
