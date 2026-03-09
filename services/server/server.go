package server

import (
	"context"
	"errors"

	"github.com/DaevMithran/mini-hsm/services/keystore"
	types "github.com/DaevMithran/mini-hsm/types/hsm/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Server struct {
	types.UnimplementedMsgServer
	types.UnimplementedQueryServer
	store *keystore.KeyStore
}

func NewServer(store *keystore.KeyStore) *Server {
	return &Server{store: store}
}

// CreateKey creates a new ECDSA P-256 key pair.
func (s *Server) CreateKey(_ context.Context, req *types.MsgCreateKeyRequest) (*types.MsgCreateKeyResponse, error) {
	metadata, err := s.store.CreateKey()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "key generation failed: %v", err)
	}

	return &types.MsgCreateKeyResponse{
		Key: metadata,
	}, nil
}

// Sign signs arbitrary data with the key identified by kid.
func (s *Server) Sign(_ context.Context, req *types.MsgSignRequest) (*types.MsgSignResponse, error) {
	if req.GetKid() == "" {
		return nil, status.Error(codes.InvalidArgument, "kid is required")
	}
	if len(req.GetData()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "data must not be empty")
	}

	sig, err := s.store.Sign(req.GetKid(), req.GetData())
	if err != nil {
		if errors.Is(err, keystore.ErrorKeyNotFound) {
			return nil, status.Error(codes.NotFound, keystore.ErrorKeyNotFound.Error())
		}
		return nil, status.Errorf(codes.Internal, "signing failed: %v", err)
	}

	return &types.MsgSignResponse{Signature: sig}, nil
}

// Verify checks a signature against data using the specified key.
func (s *Server) Verify(_ context.Context, req *types.MsgVerifyRequest) (*types.MsgVerifyResponse, error) {
	if req.GetKid() == "" {
		return nil, status.Error(codes.InvalidArgument, "kid is required")
	}
	if len(req.GetData()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "data must not be empty")
	}
	if len(req.GetSignature()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "signature must not be empty")
	}

	valid, err := s.store.Verify(req.GetKid(), req.GetData(), req.GetSignature(), nil)
	if err != nil {
		if errors.Is(err, keystore.ErrorKeyNotFound) {
			return nil, status.Error(codes.NotFound, keystore.ErrorKeyNotFound.Error())
		}
		return nil, status.Errorf(codes.Internal, "verification failed: %v", err)
	}

	return &types.MsgVerifyResponse{Valid: valid}, nil
}

// GetPublicKey returns the PEM-encoded public key for the given kid.
func (s *Server) GetPublicKey(_ context.Context, req *types.QueryGetPublicKeyRequest) (*types.QueryGetPublicKeyResponse, error) {
	if req.GetKid() == "" {
		return nil, status.Error(codes.InvalidArgument, "kid is required")
	}

	publicKeyPem, err := s.store.GetPublicKey(req.GetKid())
	if err != nil {
		if errors.Is(err, keystore.ErrorKeyNotFound) {
			return nil, status.Error(codes.NotFound, keystore.ErrorKeyNotFound.Error())
		}
		return nil, status.Errorf(codes.Internal, "public key export failed: %v", err)
	}

	return &types.QueryGetPublicKeyResponse{PublicKeyPem: publicKeyPem}, nil
}

// ListKeys returns metadata for all managed keys.
func (s *Server) ListKeys(_ context.Context, _ *types.QueryListKeysRequest) (*types.QueryListKeysResponse, error) {
	metadatas := s.store.ListKeys()
	resp := &types.QueryListKeysResponse{
		Keys: metadatas,
	}

	return resp, nil
}

// RotateKey generates a new private key for an existing kid.
func (s *Server) RotateKey(_ context.Context, req *types.MsgRotateKeyRequest) (*types.MsgRotateKeyResponse, error) {
	if req.GetKid() == "" {
		return nil, status.Error(codes.InvalidArgument, "kid is required")
	}

	metadata, err := s.store.RotateKey(req.GetKid())
	if err != nil {
		if errors.Is(err, keystore.ErrorKeyNotFound) {
			return nil, status.Error(codes.NotFound, keystore.ErrorKeyNotFound.Error())
		}
		return nil, status.Errorf(codes.Internal, "rotation failed: %v", err)
	}

	return &types.MsgRotateKeyResponse{
		Metadata: metadata,
	}, nil
}
