//go:build windows
// +build windows

package run

import "flag"

func parsePlatformFlags(flags *flag.FlagSet, c *agentConfig) {
	flags.IntVar(&c.TCPSocketPort, "tcpSpcketPort", 0, "Port number of the local address to bind the SPIRE Agent API socket to")
}
