package agent

import (
	"errors"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/mitchellh/cli"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	agentv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/agent/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/cmd/spire-server/util"
	common_cli "github.com/spiffe/spire/pkg/common/cli"

	"golang.org/x/net/context"
)

type listCommand struct {
	// Attestation type of agents to list
	byAttestationType string

	// Type and value are delimited by a colon (:)
	// ex. "unix:uid:1000" or "spiffe_id:spiffe://example.org/foo"
	selectors StringsFlag

	// Match used when filtering agents by selectors
	matchSelectorsOn string
}

// NewListCommand creates a new "list" subcommand for "agent" command.
func NewListCommand() cli.Command {
	return NewListCommandWithEnv(common_cli.DefaultEnv)
}

// NewListCommandWithEnv creates a new "list" subcommand for "agent" command
// using the environment specified
func NewListCommandWithEnv(env *common_cli.Env) cli.Command {
	return util.AdaptCommand(env, new(listCommand))
}

func (*listCommand) Name() string {
	return "agent list"
}

func (listCommand) Synopsis() string {
	return "Lists attested agents and their SPIFFE IDs"
}

// Run lists attested agents
func (c *listCommand) Run(ctx context.Context, env *common_cli.Env, serverClient util.ServerClient) error {
	filter := &agentv1.ListAgentsRequest_Filter{}
	if len(c.selectors) > 0 {
		matchBehavior, err := parseToSelectorMatch(c.matchSelectorsOn)
		if err != nil {
			return err
		}

		selectors := make([]*types.Selector, len(c.selectors))
		for i, sel := range c.selectors {
			selector, err := parseSelector(sel)
			if err != nil {
				return fmt.Errorf("error parsing selectors: %w", err)
			}
			selectors[i] = selector
		}
		filter.BySelectorMatch = &types.SelectorMatch{
			Selectors: selectors,
			Match:     matchBehavior,
		}
	}

	if c.byAttestationType != "" {
		filter.ByAttestationType = c.byAttestationType
	}

	agentClient := serverClient.NewAgentClient()
	listResponse, err := agentClient.ListAgents(ctx, &agentv1.ListAgentsRequest{
		Filter: filter,
	})
	if err != nil {
		return err
	}

	if len(listResponse.Agents) == 0 {
		return env.Printf("No attested agents found\n")
	}

	msg := fmt.Sprintf("Found %d attested ", len(listResponse.Agents))
	msg = util.Pluralizer(msg, "agent", "agents", len(listResponse.Agents))
	env.Printf(msg + ":\n\n")

	return printAgents(env, listResponse.Agents...)
}

func (c *listCommand) AppendFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.byAttestationType, "byAttestationType", "", "The Attestation type of the Agents to be listed")
	fs.StringVar(&c.matchSelectorsOn, "matchSelectorsOn", "superset", "The match mode used when filtering by selectors. Options: exact, any, superset and subset")
	fs.Var(&c.selectors, "selector", "A colon-delimited type:value selector. Can be used more than once")
}

func printAgents(env *common_cli.Env, agents ...*types.Agent) error {
	for _, agent := range agents {
		id, err := spiffeid.New(agent.Id.TrustDomain, agent.Id.Path)
		if err != nil {
			return err
		}

		if err := env.Printf("SPIFFE ID         : %s\n", id.String()); err != nil {
			return err
		}
		if err := env.Printf("Attestation type  : %s\n", agent.AttestationType); err != nil {
			return err
		}
		if err := env.Printf("Expiration time   : %s\n", time.Unix(agent.X509SvidExpiresAt, 0)); err != nil {
			return err
		}
		if err := env.Printf("Serial number     : %s\n", agent.X509SvidSerialNumber); err != nil {
			return err
		}
		if err := env.Println(); err != nil {
			return err
		}
	}

	return nil
}

func parseSelector(str string) (*types.Selector, error) {
	parts := strings.SplitAfterN(str, ":", 2)
	if len(parts) < 2 {
		return nil, fmt.Errorf("selector \"%s\" must be formatted as type:value", str)
	}

	s := &types.Selector{
		// Strip the trailing delimiter
		Type:  strings.TrimSuffix(parts[0], ":"),
		Value: parts[1],
	}
	return s, nil
}

func parseToSelectorMatch(match string) (types.SelectorMatch_MatchBehavior, error) {
	switch match {
	case "exact":
		return types.SelectorMatch_MATCH_EXACT, nil
	case "any":
		return types.SelectorMatch_MATCH_ANY, nil
	case "superset":
		return types.SelectorMatch_MATCH_SUPERSET, nil
	case "subset":
		return types.SelectorMatch_MATCH_SUBSET, nil
	default:
		return types.SelectorMatch_MATCH_SUPERSET, errors.New("unsupported match behavior")
	}
}

// StringsFlag defines a custom type for string lists. Doing
// this allows us to support repeatable string flags.
type StringsFlag []string

// String returns the string flag.
func (s *StringsFlag) String() string {
	return fmt.Sprint(*s)
}

// Set appends the string flag.
func (s *StringsFlag) Set(val string) error {
	*s = append(*s, val)
	return nil
}
