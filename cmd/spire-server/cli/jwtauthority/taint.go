package jwtauthority

import (
	"context"
	"flag"

	"github.com/mitchellh/cli"
	localauthorityv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/localauthority/v1"
	"github.com/spiffe/spire/cmd/spire-server/util"
	common_cli "github.com/spiffe/spire/pkg/common/cli"
)

type taintCommand struct {
	keyID string
}

func NewTaintCommand() cli.Command {
	return NewTaintCommandWithEnv(common_cli.DefaultEnv)
}

func NewTaintCommandWithEnv(env *common_cli.Env) cli.Command {
	return util.AdaptCommand(env, new(taintCommand))
}

func (*taintCommand) Name() string {
	return "localauthority JWT taint"
}

func (taintCommand) Synopsis() string {
	return "Taint an OLD JWT authority"
}

// Run counts attested entries
func (c *taintCommand) Run(ctx context.Context, env *common_cli.Env, serverClient util.ServerClient) error {
	localauthorityClient := serverClient.NewLocalAuthorityClient()
	taintResp, err := localauthorityClient.TaintJWTAuthority(ctx, &localauthorityv1.TaintJWTAuthorityRequest{
		KeyId: c.keyID,
	})
	if err != nil {
		return err
	}
	state := taintResp.TaintedAuthority
	pKey := getPublicKeyBlock(state)
	env.Printf("%q: \n%s\n", state.Status.String(), pKey)
	return nil
}

func (c *taintCommand) AppendFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.keyID, "keyID", "", "Key id of the JWT authority to taint")
}
