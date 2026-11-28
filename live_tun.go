package box

import (
	"errors"
	"reflect"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/tun"
	"github.com/sagernet/sing/service"
)

func (h *liveRuntime) prepareTun(old, next []option.Inbound) (func() error, error) {
	if len(old) != len(next) {
		return nil, errors.New("live configuration cannot replace listening sockets")
	}
	var change func() error
	for i, a := range old {
		b := next[i]
		if reflect.DeepEqual(a, b) {
			continue
		}
		before, ok := a.Options.(*option.TunInboundOptions)
		after, isTun := b.Options.(*option.TunInboundOptions)
		if !ok || !isTun || a.Tag != b.Tag || a.Type != b.Type || change != nil {
			return nil, errors.New("unexpected listener change")
		}
		if before.MTU != after.MTU && (after.MTU != 1400 && after.MTU != 1500) {
			return nil, errors.New("unsupported desktop MTU")
		}
		fixed := *after
		fixed.MTU = before.MTU
		fixed.RouteExcludeAddress = before.RouteExcludeAddress
		fixed.AutoRedirect = before.AutoRedirect
		if !reflect.DeepEqual(&fixed, before) {
			return nil, errors.New("unexpected TUN identity change")
		}
		current, ok := h.box.inbound.Get(a.Tag)
		t, typed := current.(*tun.Inbound)
		if !ok || !typed {
			return nil, errors.New("active TUN disappeared")
		}
		// Stock sing-tun lacks the desktop policy-rule update. The release build
		// supplies it; standalone builds can rebind just this inbound.
		// The Go stack uses the startup MTU to size packets and buffers.
		if before.MTU != after.MTU && (before.Stack == "" || before.Stack == "go") ||
			before.AutoRedirect != after.AutoRedirect && !t.CanSwitchRedirect() {
			change = func() error { return h.replaceTun(current, a, b) }
		} else {
			change = func() error { return t.UpdateDesktopOptions(before, after) }
		}
	}
	return change, nil
}

func (h *liveRuntime) replaceTun(current adapter.Inbound, before, after option.Inbound) error {
	ctx := h.box.scope.Context()
	registry := service.FromContext[adapter.InboundRegistry](ctx)
	open := func(o option.Inbound) (adapter.Inbound, *adapter.Scope, error) {
		ingress := &liveIngress{h.view}
		t, err := registry.Create(ctx, ingress, h.box.logger, o.Tag, o.Type, o.Options)
		if err != nil {
			return nil, nil, err
		}
		scope := adapter.NewScope(ctx, h.box.logger)
		for _, stage := range adapter.ListStartStages {
			if err = t.Start(stage, scope); err != nil {
				_ = scope.Close()
				return nil, nil, err
			}
		}
		return t, scope, nil
	}
	prev := h.tunScope
	if prev == nil {
		prev = h.box.scope.Child(h.box.inbound).Child(current)
	}
	if prev == nil {
		return errors.New("TUN lifetime unavailable")
	}
	if err := prev.Close(); err != nil {
		return err
	}
	t, scope, err := open(after)
	if err != nil {
		var recovery error
		t, scope, recovery = open(before)
		if recovery != nil {
			return errors.Join(err, recovery)
		}
	}
	h.box.inbound.Replace(current, t)
	h.tunScope = scope
	return err
}
