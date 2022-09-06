package x509authority

import (
	"context"
	"flag"

	"github.com/mitchellh/cli"
	localauthorityv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/localauthority/v1"
	"github.com/spiffe/spire/cmd/spire-server/util"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
)

type prepareCommand struct{}

func NewPrepareCommand() cli.Command {
	return NewPrepareCommandWithEnv(common_cli.DefaultEnv)
}

func NewPrepareCommandWithEnv(env *common_cli.Env) cli.Command {
	return util.AdaptCommand(env, new(prepareCommand))
}

func (*prepareCommand) Name() string {
	return "localauthority x509 prepare"
}

func (*prepareCommand) Synopsis() string {
	return "Prepare a new X.509 authority"
}

// Run counts attested entries
func (c *prepareCommand) Run(ctx context.Context, env *common_cli.Env, serverClient util.ServerClient) error {
	localauthorityClient := serverClient.NewLocalAuthorityClient()
	preparedResp, err := localauthorityClient.PrepareX509Authority(ctx, &localauthorityv1.PrepareX509AuthorityRequest{})
	if err != nil {
		return err
	}
	state := preparedResp.PreparedAuthority
	pKey := getPublicKeyBlock(state)
	env.Printf("%q: \n%s\n", state.Status.String(), pKey)
	return nil
}

func (c *prepareCommand) AppendFlags(fs *flag.FlagSet) {
}
