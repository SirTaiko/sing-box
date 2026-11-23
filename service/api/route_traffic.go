package api

import (
	"time"

	"github.com/sagernet/sing-box/common/trafficcontrol"
	"github.com/sagernet/sing-box/daemon"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

type routeTrafficService struct {
	daemon.UnimplementedRouteTrafficServer
	manager *trafficcontrol.Manager
}

func (s *routeTrafficService) Subscribe(_ *emptypb.Empty, stream grpc.ServerStreamingServer[daemon.RouteTrafficTotals]) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var previous time.Time
	for {
		now := time.Now()
		totals := s.manager.RouteTrafficTotals()
		sample := &daemon.RouteTrafficTotals{
			VpnUpload: totals.VPNUp, VpnDownload: totals.VPNDown,
			DirectUpload: totals.DirectUp, DirectDownload: totals.DirectDown,
		}
		if !previous.IsZero() {
			sample.ElapsedNanos = uint64(now.Sub(previous))
		}
		if err := stream.Send(sample); err != nil {
			return err
		}
		previous = now
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case <-ticker.C:
		}
	}
}
