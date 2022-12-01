package jwtauthority

import (
	"encoding/pem"

	localauthorityv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/localauthority/v1"
)

func getPublicKeyBlock(s *localauthorityv1.AuthorityState) string {
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: s.PublicKey,
	}
	return string(pem.EncodeToMemory(block))
}
