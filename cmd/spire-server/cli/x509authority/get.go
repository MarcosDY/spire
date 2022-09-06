package x509authority

import (
	"context"
	"flag"

	"github.com/mitchellh/cli"
	localauthorityv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/localauthority/v1"
	"github.com/spiffe/spire/cmd/spire-server/util"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
)

type getCommand struct{}

func NewGetCommand() cli.Command {
	return NewGetCommandWithEnv(common_cli.DefaultEnv)
}

func NewGetCommandWithEnv(env *common_cli.Env) cli.Command {
	return util.AdaptCommand(env, new(getCommand))
}

func (*getCommand) Name() string {
	return "localauthority x509 get"
}

func (getCommand) Synopsis() string {
	return "Get all X.509 local authorities"
}

// Run counts attested entries
func (c *getCommand) Run(ctx context.Context, env *common_cli.Env, serverClient util.ServerClient) error {
	localauthorityClient := serverClient.NewLocalAuthorityClient()
	getResp, err := localauthorityClient.GetX509AuthorityState(ctx, &localauthorityv1.GetX509AuthorityStateRequest{})
	if err != nil {
		return err
	}

	for _, state := range getResp.States {
		pKey := getPublicKeyBlock(state)
		env.Printf("%q: \n%s\n", state.Status.String(), pKey)
	}

	return nil
}

func (c *getCommand) AppendFlags(fs *flag.FlagSet) {
}
