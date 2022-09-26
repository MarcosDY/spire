package localauthority

import (
	"context"
	"crypto/x509"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	localauthorityv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/localauthority/v1"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/pkg/server/ca"
	"github.com/spiffe/spire/pkg/server/datastore"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Config struct {
	TrustDomain spiffeid.TrustDomain
	DataStore   datastore.DataStore
	Manager     ca.AutorityUpdater
}

type Service struct {
	localauthorityv1.UnsafeLocalAuthorityServer

	td spiffeid.TrustDomain
	ds datastore.DataStore
	m  ca.AutorityUpdater
}

func New(config Config) *Service {
	return &Service{
		ds: config.DataStore,
		td: config.TrustDomain,
		m:  config.Manager,
	}
}

func (s *Service) GetJWTAuthorityState(ctx context.Context, _ *localauthorityv1.GetJWTAuthorityStateRequest) (*localauthorityv1.GetJWTAuthorityStateResponse, error) {
	var states []*localauthorityv1.AuthorityState

	for _, authority := range s.m.GetJWTAuthorities() {
		state, err := protoFromKeyState(authority)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to parse authority: %v", err)
		}

		states = append(states, state)
	}

	return &localauthorityv1.GetJWTAuthorityStateResponse{
		States: states,
	}, nil
}

func (s *Service) PrepareJWTAuthority(ctx context.Context, req *localauthorityv1.PrepareJWTAuthorityRequest) (*localauthorityv1.PrepareJWTAuthorityResponse, error) {
	authority, err := s.m.PrepareJWTAuthority(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to prepare a new JWT Authotority: %v", err)
	}

	preparedAuthority, err := protoFromKeyState(authority)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to parse authority: %v", err)
	}

	return &localauthorityv1.PrepareJWTAuthorityResponse{
		PreparedAuthority: preparedAuthority,
	}, nil
}

func (s *Service) ActivateJWTAuthority(context.Context, *localauthorityv1.ActivateJWTAuthorityRequest) (*localauthorityv1.ActivateJWTAuthorityResponse, error) {
	authority, err := s.m.ActivateJWTAuthority()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to activate JWT Authotority: %v", err)
	}

	activatedAuthority, err := protoFromKeyState(authority)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to parse authority: %v", err)
	}

	return &localauthorityv1.ActivateJWTAuthorityResponse{
		ActivatedAuthority: activatedAuthority,
	}, nil
}

func (s *Service) TaintJWTAuthority(ctx context.Context, _ *localauthorityv1.TaintJWTAuthorityRequest) (*localauthorityv1.TaintJWTAuthorityResponse, error) {
	authority, err := s.m.TaintJWTAuthority(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to taint authority: %v", err)
	}

	taintedAuthority, err := protoFromKeyState(authority)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to parse authority: %v", err)
	}

	return &localauthorityv1.TaintJWTAuthorityResponse{
		TaintedAuthority: taintedAuthority,
	}, nil
}

func (s *Service) RevokeJWTAuthority(ctx context.Context, req *localauthorityv1.RevokeJWTAuthorityRequest) (*localauthorityv1.RevokeJWTAuthorityResponse, error) {
	authority, err := s.m.RevokeJWTAuthority(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to revoke JWT authority: %v", err)
	}

	revokedAuthority, err := protoFromKeyState(authority)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to parse authority: %v", err)
	}

	return &localauthorityv1.RevokeJWTAuthorityResponse{
		RevokedAuthority: revokedAuthority,
	}, nil
}

func (s *Service) ReactivateJWTAuthoriry(context.Context, *localauthorityv1.ReactivateJWTAuthorityRequest) (*localauthorityv1.ReactivateJWTAuthorityResponse, error) {
	return nil, status.Error(codes.Unimplemented, "unimplemented")
}

func (s *Service) GetX509AuthorityState(ctx context.Context, _ *localauthorityv1.GetX509AuthorityStateRequest) (*localauthorityv1.GetX509AuthorityStateResponse, error) {
	log := rpccontext.Logger(ctx)

	var states []*localauthorityv1.AuthorityState
	for _, authority := range s.m.GetX509Authorities() {
		state, err := protoFromKeyState(authority)
		if err != nil {
			log.WithError(err).Error("Failed to parse getted authoriry")
			return nil, status.Errorf(codes.Internal, "failed to parse authority: %v", err)
		}

		states = append(states, state)
	}

	return &localauthorityv1.GetX509AuthorityStateResponse{
		States: states,
	}, nil
}

func (s *Service) PrepareX509Authority(ctx context.Context, req *localauthorityv1.PrepareX509AuthorityRequest) (*localauthorityv1.PrepareX509AuthorityResponse, error) {
	authority, err := s.m.PrepareX509Authority(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to prepare a new X.509 Authotority: %v", err)
	}

	preparedAuthority, err := protoFromKeyState(authority)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to parse authority: %v", err)
	}

	return &localauthorityv1.PrepareX509AuthorityResponse{
		PreparedAuthority: preparedAuthority,
	}, nil
}

func (s *Service) ActivateX509Authority(context.Context, *localauthorityv1.ActivateX509AuthorityRequest) (*localauthorityv1.ActivateX509AuthorityResponse, error) {
	authority, err := s.m.ActivateX509Authority()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to activate X.509 Authotority: %v", err)
	}

	activatedAuthority, err := protoFromKeyState(authority)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to parse authority: %v", err)
	}

	return &localauthorityv1.ActivateX509AuthorityResponse{
		ActivatedAuthority: activatedAuthority,
	}, nil
}

func (s *Service) TaintX509Authority(ctx context.Context, _ *localauthorityv1.TaintX509AuthorityRequest) (*localauthorityv1.TaintX509AuthorityResponse, error) {
	log := rpccontext.Logger(ctx)
	authority, err := s.m.TaintX509Authority(ctx)
	if err != nil {
		// TODO: replace all this status creating for api call with error function
		log.WithError(err).Error("Failed to taint authoriry")
		return nil, status.Errorf(codes.Internal, "failed to taint authority: %v", err)
	}

	taintedAuthority, err := protoFromKeyState(authority)
	if err != nil {
		log.WithError(err).Error("Failed to parse authoriry")
		return nil, status.Errorf(codes.Internal, "failed to parse authority: %v", err)
	}

	return &localauthorityv1.TaintX509AuthorityResponse{
		TaintedAuthority: taintedAuthority,
	}, nil
}

func (s *Service) RevokeX509Authority(ctx context.Context, _ *localauthorityv1.RevokeX509AuthorityRequest) (*localauthorityv1.RevokeX509AuthorityResponse, error) {
	authority, err := s.m.RevokeX509Authority(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to revoke X.509 authority: %v", err)
	}

	revokedAuthority, err := protoFromKeyState(authority)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to parse authority: %v", err)
	}

	return &localauthorityv1.RevokeX509AuthorityResponse{
		RevokedAuthority: revokedAuthority,
	}, nil
}

func (s *Service) ReactivateX509Authoriry(context.Context, *localauthorityv1.ReactivateX509AuthorityRequest) (*localauthorityv1.ReactivateX509AuthorityResponse, error) {
	return nil, status.Error(codes.Unimplemented, "unimplemented")
}

func protoFromKeyState(state *ca.KeyState) (*localauthorityv1.AuthorityState, error) {
	pKey, err := x509.MarshalPKIXPublicKey(state.PublicKey)
	if err != nil {
		return nil, err
	}

	var status localauthorityv1.AuthorityState_Status
	switch state.Status {
	case ca.Active:
		status = localauthorityv1.AuthorityState_ACTIVE
	case ca.Prepared:
		status = localauthorityv1.AuthorityState_PREPARED
	case ca.Old:
		status = localauthorityv1.AuthorityState_OLD
	}

	return &localauthorityv1.AuthorityState{
		PublicKey: pKey,
		Status:    status,
	}, nil
}
