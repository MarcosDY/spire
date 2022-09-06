package x509authority

import (
	"context"
	"flag"

	"github.com/mitchellh/cli"
	localauthorityv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/localauthority/v1"
	"github.com/spiffe/spire/cmd/spire-server/util"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
)

type activateCommand struct{}

func NewActivateCommand() cli.Command {
	return NewActivateCommandWithEnv(common_cli.DefaultEnv)
}

func NewActivateCommandWithEnv(env *common_cli.Env) cli.Command {
	return util.AdaptCommand(env, new(activateCommand))
}

func (*activateCommand) Name() string {
	return "localauthority x509 activate"
}

func (*activateCommand) Synopsis() string {
	return "Activate a prepared X.509 authority"
}

// Run counts attested entries
func (c *activateCommand) Run(ctx context.Context, env *common_cli.Env, serverClient util.ServerClient) error {
	localauthorityClient := serverClient.NewLocalAuthorityClient()
	activateResp, err := localauthorityClient.ActivateX509Authority(ctx, &localauthorityv1.ActivateX509AuthorityRequest{})
	if err != nil {
		return err
	}
	state := activateResp.ActivatedAuthority
	pKey := getPublicKeyBlock(state)
	env.Printf("%q: \n%s\n", state.Status.String(), pKey)
	return nil
}

func (c *activateCommand) AppendFlags(fs *flag.FlagSet) {
}
