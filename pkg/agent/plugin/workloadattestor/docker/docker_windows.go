package docker

import (
	"fmt"

	"github.com/spiffe/spire/pkg/agent/plugin/workloadattestor/docker/process"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func validateOS(c *dockerPluginConfig) error {
	if c.DockerSocketPath != "" {
		return status.Error(codes.InvalidArgument, "invalid configuration: docker_socket_path is not supported in this platform; please use docker_host instead")
	}

	if len(c.ContainerIDCGroupMatchers) > 0 {
		return status.Error(codes.InvalidArgument, "invalid configuration: container_id_cgroup_matchers is not supported in this platform")
	}

	return nil
}

func getDockerHost(c *dockerPluginConfig) string {
	return c.DockerHost
}

func getContainerID(pID int32) (string, error) {
	fmt.Printf("--- inside get container ID: %v\n", pID)
	containerID, err := process.GetContainerIDByProcess(pID)
	if err != nil {
		fmt.Printf("--- Err: %v\n", err)
		return "", status.Errorf(codes.Internal, "failed to get container ID: %v", err)
	}
	return containerID, nil
}
