package api

import (
	"context"
	"net"
	"net/http"
	"net/netip"

	"github.com/sagernet/sing-box/adapter"
	boxService "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/daemon"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
	"github.com/sagernet/sing/service"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c" //nolint:staticcheck
)

func RegisterService(registry *boxService.Registry) {
	boxService.Register[option.APIServiceOptions](registry, C.TypeAPI, NewService)
}

type Service struct {
	boxService.Adapter
	logger    log.ContextLogger
	options   option.APIServiceOptions
	listener  *listener.Listener
	tlsConfig tls.ServerConfig
	dashboard *dashboard
}

func NewService(ctx context.Context, logger log.ContextLogger, tag string, options option.APIServiceOptions) (adapter.Service, error) {
	s := &Service{
		Adapter: boxService.NewAdapter(C.TypeAPI, tag),
		logger:  logger,
		options: options,
		listener: listener.New(listener.Options{
			Context: ctx,
			Logger:  logger,
			Network: []string{N.NetworkTCP},
			Listen:  options.ListenOptions,
		}),
	}
	if options.TLS != nil {
		tlsConfig, err := tls.NewServer(ctx, logger, common.PtrValueOrDefault(options.TLS))
		if err != nil {
			return nil, err
		}
		s.tlsConfig = tlsConfig
	}
	if options.Dashboard != nil && options.Dashboard.Enabled {
		s.dashboard = newDashboard(ctx, logger, *options.Dashboard)
	}
	return s, nil
}

func (s *Service) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStarted {
		return nil
	}
	ctx := scope.Context()
	var runtime adapter.RuntimeConfig
	if s.Tag() == "mvpn-api" && s.options.Secret != "" && s.options.Listen != nil && s.options.Listen.Build(netip.Addr{}).IsLoopback() {
		runtime = service.FromContext[adapter.RuntimeConfig](ctx)
		if runtime != nil {
			ctx = runtime.ServiceContext(ctx)
		}
	}
	startedService := daemon.NewAttachedService(ctx)
	scope.Add(func() error {
		startedService.Close()
		return nil
	})
	grpcServer := daemon.NewServer(startedService, s.options.Secret)
	if runtime != nil {
		daemon.RegisterRuntimeConfigServer(grpcServer, &runtimeConfig{host: runtime})
	}
	if s.options.Secret != "" {
		daemon.RegisterDNSLookupServer(grpcServer, &dnsLookup{
			router:     service.FromContext[adapter.DNSRouter](ctx),
			transports: service.FromContext[adapter.DNSTransportManager](ctx),
		})
	}
	scope.Add(func() error {
		grpcServer.Stop()
		return nil
	})
	if s.dashboard != nil {
		err := s.dashboard.start(ctx)
		if err != nil {
			return E.Cause(err, "start dashboard")
		}
		scope.Add(s.dashboard.close)
	}
	httpServer := &http.Server{
		//nolint:staticcheck
		Handler: h2c.NewHandler(newHTTPHandler(s.logger, grpcServer, s.options, s.dashboard), new(http2.Server)),
		BaseContext: func(net.Listener) context.Context {
			return ctx
		},
	}
	if s.tlsConfig != nil {
		err := s.tlsConfig.Start()
		if err != nil {
			return E.Cause(err, "create TLS config")
		}
		scope.Add(s.tlsConfig.Close)
		if !common.Contains(s.tlsConfig.NextProtos(), http2.NextProtoTLS) {
			s.tlsConfig.SetNextProtos(append([]string{http2.NextProtoTLS}, s.tlsConfig.NextProtos()...))
		}
		if !common.Contains(s.tlsConfig.NextProtos(), "http/1.1") {
			s.tlsConfig.SetNextProtos(append(s.tlsConfig.NextProtos(), "http/1.1"))
		}
	}
	tcpListener, err := s.listener.ListenTCP()
	if err != nil {
		return err
	}
	scope.Add(s.listener.Close)
	if s.tlsConfig != nil {
		tcpListener = aTLS.NewListener(tcpListener, s.tlsConfig)
	}
	scope.Add(httpServer.Close)
	go func() {
		serveErr := httpServer.Serve(tcpListener)
		if serveErr != nil && ctx.Err() == nil {
			s.logger.Error("serve error: ", serveErr)
		}
	}()
	return nil
}
