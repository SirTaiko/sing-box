package trafficcontrol

import (
	"strings"
	"sync/atomic"
)

type routeBytes struct {
	upload   atomic.Int64
	download atomic.Int64
}

// Independent cache lines keep unrelated high-throughput connections from
// updating the same counters on every copy. The connection already has a UUID.
type routeTrafficShard struct {
	vpn    routeBytes
	direct routeBytes
	_      [32]byte
}

type routeTrafficShards [16]routeTrafficShard

type RouteTrafficTotals struct {
	VPNUp, VPNDown, DirectUp, DirectDown uint64
}

// EnableRouteTraffic runs during box construction, before inbounds start.
func (m *Manager) EnableRouteTraffic() {
	m.routeTraffic = new(routeTrafficShards)
}

func (m *Manager) routeCounter(metadata *TrackerMetadata) *routeBytes {
	if m.routeTraffic == nil {
		return nil
	}
	shard := &m.routeTraffic[int(metadata.ID[0])%len(m.routeTraffic)]
	var direct *routeBytes
	for _, tag := range metadata.Chain {
		switch tag {
		case "vpn-select", "auto", "vless-reality", "hysteria2",
			"vless-poland", "hysteria2-poland", "vless-lithuania", "hysteria2-lithuania":
			return &shard.vpn
		case "direct", "zapret":
			direct = &shard.direct
		default:
			if strings.HasPrefix(tag, "mvpn-zapret-") {
				direct = &shard.direct
			}
		}
	}
	return direct
}

func (m *TrackerMetadata) byteCounters() ([]*atomic.Int64, []*atomic.Int64) {
	if m.routeBytes == nil {
		return []*atomic.Int64{m.Upload}, []*atomic.Int64{m.Download}
	}
	return []*atomic.Int64{m.Upload, &m.routeBytes.upload}, []*atomic.Int64{m.Download, &m.routeBytes.download}
}

func (m *Manager) RouteTrafficTotals() RouteTrafficTotals {
	var totals RouteTrafficTotals
	if m.routeTraffic != nil {
		for i := range m.routeTraffic {
			shard := &m.routeTraffic[i]
			totals.VPNUp += uint64(shard.vpn.upload.Load())
			totals.VPNDown += uint64(shard.vpn.download.Load())
			totals.DirectUp += uint64(shard.direct.upload.Load())
			totals.DirectDown += uint64(shard.direct.download.Load())
		}
	}
	return totals
}
