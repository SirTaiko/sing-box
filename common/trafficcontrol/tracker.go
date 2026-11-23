package trafficcontrol

import (
	"context"
	"net"
	"slices"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"

	"github.com/gofrs/uuid/v5"
)

type TrackerMetadata struct {
	routeBytes   *routeBytes
	ID           uuid.UUID
	Metadata     adapter.InboundContext
	CreatedAt    time.Time
	ClosedAt     time.Time
	Upload       *atomic.Int64
	Download     *atomic.Int64
	Chain        []string
	Rule         adapter.Rule
	Outbound     string
	OutboundType string
}

type Tracker interface {
	Metadata() *TrackerMetadata
	Close() error
}

func (m *Manager) RoutedConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) net.Conn {
	info := m.newTrackerMetadata(metadata, matchedRule)
	upload, download := info.byteCounters()
	tracker := &connTracker{
		ExtendedConn: bufio.NewInt64CounterConn(conn, upload, download),
		metadata:     info,
		manager:      m,
	}
	m.join(tracker)
	return tracker
}

func (m *Manager) RoutedPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) N.PacketConn {
	info := m.newTrackerMetadata(metadata, matchedRule)
	upload, download := info.byteCounters()
	tracker := &packetConnTracker{
		PacketConn: bufio.NewInt64CounterPacketConn(conn, upload, nil, download, nil),
		metadata:   info,
		manager:    m,
	}
	m.join(tracker)
	return tracker
}

func (m *Manager) RoutedFlow(ctx context.Context, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) tun.FlowTracker {
	return &flowTracker{
		metadata: m.newTrackerMetadata(metadata, matchedRule),
		manager:  m,
	}
}

func (m *Manager) newTrackerMetadata(metadata adapter.InboundContext, matchedRule adapter.Rule) TrackerMetadata {
	id, _ := uuid.NewV4()
	chain := common.Map(metadata.OutboundChain, adapter.Outbound.Tag)
	slices.Reverse(chain)
	outbound := metadata.OutboundChain[len(metadata.OutboundChain)-1]
	info := TrackerMetadata{
		ID:           id,
		Metadata:     metadata,
		CreatedAt:    time.Now(),
		Upload:       new(atomic.Int64),
		Download:     new(atomic.Int64),
		Chain:        chain,
		Rule:         matchedRule,
		Outbound:     outbound.Tag(),
		OutboundType: outbound.Type(),
	}
	info.routeBytes = m.routeCounter(&info)
	return info
}

type connTracker struct {
	N.ExtendedConn
	metadata TrackerMetadata
	manager  *Manager
}

func (t *connTracker) Metadata() *TrackerMetadata {
	return &t.metadata
}

func (t *connTracker) Close() error {
	t.manager.leave(t)
	return t.ExtendedConn.Close()
}

func (t *connTracker) Upstream() any {
	return t.ExtendedConn
}

func (t *connTracker) ReaderReplaceable() bool {
	return true
}

func (t *connTracker) WriterReplaceable() bool {
	return true
}

var (
	_ Tracker         = (*flowTracker)(nil)
	_ tun.FlowTracker = (*flowTracker)(nil)
)

type flowTracker struct {
	metadata TrackerMetadata
	manager  *Manager
	handle   tun.FlowHandle
}

func (t *flowTracker) Metadata() *TrackerMetadata {
	return &t.metadata
}

func (t *flowTracker) AttachFlow(handle tun.FlowHandle) {
	t.handle = handle
	t.manager.join(t)
}

func (t *flowTracker) CountForward(n int) {
	t.metadata.Upload.Add(int64(n))
	if totals := t.metadata.routeBytes; totals != nil {
		totals.upload.Add(int64(n))
	}
}

func (t *flowTracker) CountReverse(n int) {
	t.metadata.Download.Add(int64(n))
	if totals := t.metadata.routeBytes; totals != nil {
		totals.download.Add(int64(n))
	}
}

func (t *flowTracker) FlowEstablished() {
}

func (t *flowTracker) CloseFlow(reason tun.FlowCloseReason) {
	t.manager.leave(t)
}

func (t *flowTracker) Close() error {
	handle := t.handle
	if handle != nil {
		handle.CloseFlow()
	} else {
		t.manager.leave(t)
	}
	return nil
}

type packetConnTracker struct {
	N.PacketConn
	metadata TrackerMetadata
	manager  *Manager
}

func (t *packetConnTracker) Metadata() *TrackerMetadata {
	return &t.metadata
}

func (t *packetConnTracker) Close() error {
	t.manager.leave(t)
	return t.PacketConn.Close()
}

func (t *packetConnTracker) Upstream() any {
	return t.PacketConn
}

func (t *packetConnTracker) ReaderReplaceable() bool {
	return true
}

func (t *packetConnTracker) WriterReplaceable() bool {
	return true
}
