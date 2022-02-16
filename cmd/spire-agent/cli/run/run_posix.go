//go:build !windows
// +build !windows

package run

import "flag"

func parsePlatformFlags(flags *flag.FlagSet, c *agentConfig) {
	flags.StringVar(&c.SocketPath, "socketPath", "", "Path to bind the SPIRE Agent API socket to")
}
