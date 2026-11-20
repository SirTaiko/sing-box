package api

import (
	"context"
	"crypto/sha256"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/daemon"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

type runtimeConfig struct {
	daemon.UnimplementedRuntimeConfigServer
	host adapter.RuntimeConfig
}

func (s *runtimeConfig) Apply(ctx context.Context, req *daemon.ApplyRuntimeConfigRequest) (*emptypb.Empty, error) {
	if len(req.Sha256) != sha256.Size {
		return nil, status.Error(codes.InvalidArgument, "invalid configuration digest")
	}
	if err := s.host.ApplyRuntimeConfig(ctx, req.Sha256, req.SelectedOutbound); err != nil {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	return &emptypb.Empty{}, nil
}

func (s *runtimeConfig) Status(context.Context, *emptypb.Empty) (*daemon.RuntimeRevision, error) {
	return &daemon.RuntimeRevision{Sha256: s.host.RuntimeRevision()}, nil
}
