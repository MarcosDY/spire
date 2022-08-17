package localauthority

import (
	"context"

	localauthorityv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/localauthority/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Service struct {
	localauthorityv1.UnsafeLocalAuthorityServer
}

func (s *Service) GetJWTAuthorityState(context.Context, *localauthorityv1.GetJWTAuthorityStateRequest) (*localauthorityv1.GetJWTAuthorityStateResponse, error) {
	return nil, status.Error(codes.Unimplemented, "unimplemented")
}

func (s *Service) PrepareJWTAuthority(context.Context, *localauthorityv1.PrepareJWTAuthorityRequest) (*localauthorityv1.PrepareJWTAuthorityResponse, error) {
	return nil, status.Error(codes.Unimplemented, "unimplemented")
}

func (s *Service) ActivateJWTAuthority(context.Context, *localauthorityv1.ActivateJWTAuthorityRequest) (*localauthorityv1.ActivateJWTAuthorityResponse, error) {
	return nil, status.Error(codes.Unimplemented, "unimplemented")
}

func (s *Service) TaintJWTAuthority(context.Context, *localauthorityv1.TaintJWTAuthorityRequest) (*localauthorityv1.TaintJWTAuthorityResponse, error) {
	return nil, status.Error(codes.Unimplemented, "unimplemented")
}

func (s *Service) RevokeJWTAuthority(context.Context, *localauthorityv1.RevokeJWTAuthorityRequest) (*localauthorityv1.RevokeJWTAuthorityResponse, error) {
	return nil, status.Error(codes.Unimplemented, "unimplemented")
}

func (s *Service) GetX509AuthorityState(context.Context, *localauthorityv1.GetX509AuthorityStateRequest) (*localauthorityv1.GetX509AuthorityStateResponse, error) {
	return nil, status.Error(codes.Unimplemented, "unimplemented")
}

func (s *Service) PrepareX509Authority(context.Context, *localauthorityv1.PrepareX509AuthorityRequest) (*localauthorityv1.PrepareX509AuthorityResponse, error) {
	return nil, status.Error(codes.Unimplemented, "unimplemented")
}

func (s *Service) ActivateX509Authority(context.Context, *localauthorityv1.ActivateX509AuthorityRequest) (*localauthorityv1.ActivateX509AuthorityResponse, error) {
	return nil, status.Error(codes.Unimplemented, "unimplemented")
}

func (s *Service) TaintX509Authority(context.Context, *localauthorityv1.TaintX509AuthorityRequest) (*localauthorityv1.TaintX509AuthorityResponse, error) {
	return nil, status.Error(codes.Unimplemented, "unimplemented")
}

func (s *Service) RevokeX509Authority(context.Context, *localauthorityv1.RevokeX509AuthorityRequest) (*localauthorityv1.RevokeX509AuthorityResponse, error) {
	return nil, status.Error(codes.Unimplemented, "unimplemented")
}
