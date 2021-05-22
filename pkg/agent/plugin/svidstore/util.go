package svidstore

import (
	"strings"

	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/spire/proto/spire/common"
	svidstorev1 "github.com/spiffe/spire/proto/spire/plugin/agent/svidstore/v1"
	"google.golang.org/protobuf/proto"
)

// ParseSelectors parses selectors for SVIDStore plugins
func ParseSelectors(selectors []*common.Selector) map[string]string {
	data := make(map[string]string)
	for _, s := range selectors {
		if s.Type != strings.ToLower("SVIDStore") {
			continue
		}

		value := strings.Split(s.Value, ":")
		data[value[0]] = value[1]
	}

	return data
}

// EncodeSecret creates a secrets binary from a 'workload.X509SVIDResponse'
func EncodeSecret(req *svidstorev1.PutX509SVIDRequest) ([]byte, error) {

	bundle := []byte{}
	for _, b := range req.Svid.Bundle {
		bundle = append(bundle, b...)
	}
	x509SVID := []byte{}
	for _, c := range req.Svid.CertChain {
		x509SVID = append(x509SVID, c...)
	}

	resp := &workload.X509SVIDResponse{
		Svids: []*workload.X509SVID{
			{
				SpiffeId:    req.Svid.SpiffeID,
				Bundle:      bundle,
				X509Svid:    x509SVID,
				X509SvidKey: req.Svid.PrivateKey,
			},
		},
		FederatedBundles: req.FederatedBundles,
	}
	return proto.Marshal(resp)
}
