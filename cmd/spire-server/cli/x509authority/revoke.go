package x509authority

import (
	"context"
	"flag"

	"github.com/mitchellh/cli"
	localauthorityv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/localauthority/v1"
	"github.com/spiffe/spire/cmd/spire-server/util"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
)

type revokeCommand struct{}

func NewRevokeCommand() cli.Command {
	return NewRevokeCommandWithEnv(common_cli.DefaultEnv)
}

func NewRevokeCommandWithEnv(env *common_cli.Env) cli.Command {
	return util.AdaptCommand(env, new(revokeCommand))
}

func (*revokeCommand) Name() string {
	return "localauthority x509 revoke"
}

func (*revokeCommand) Synopsis() string {
	return "Revoke an OLD X.509 authority"
}

// Run counts attested entries
func (c *revokeCommand) Run(ctx context.Context, env *common_cli.Env, serverClient util.ServerClient) error {
	localauthorityClient := serverClient.NewLocalAuthorityClient()
	revokeResp, err := localauthorityClient.RevokeX509Authority(ctx, &localauthorityv1.RevokeX509AuthorityRequest{})
	if err != nil {
		return err
	}
	state := revokeResp.RevokedAuthority
	pKey := getPublicKeyBlock(state)
	env.Printf("%q: \n%s\n", state.Status.String(), pKey)
	return nil
}

func (c *revokeCommand) AppendFlags(fs *flag.FlagSet) {
}
