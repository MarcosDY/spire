//go:build !windows

package docker

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/hashicorp/go-hclog"
	"github.com/spiffe/spire/pkg/agent/common/cgroups"
	"github.com/spiffe/spire/pkg/agent/plugin/workloadattestor/docker/cgroup"
)

type OSConfig struct {
	// DockerSocketPath is the location of the docker daemon socket, this config can be used only on unix environments (default: "unix:///var/run/docker.sock").
	DockerSocketPath string `hcl:"docker_socket_path" json:"docker_socket_path"`

	// ContainerIDCGroupMatchers is a list of patterns used to discover container IDs from cgroup entries.
	// See the documentation for cgroup.NewContainerIDFinder in the cgroup subpackage for more information. (Unix)
	ContainerIDCGroupMatchers []string `hcl:"container_id_cgroup_matchers" json:"container_id_cgroup_matchers"`
}

func createHelper(c *dockerPluginConfig) (*containerHelper, error) {
	var containerIDFinder cgroup.ContainerIDFinder = &defaultContainerIDFinder{}
	var err error
	if len(c.ContainerIDCGroupMatchers) > 0 {
		containerIDFinder, err = cgroup.NewContainerIDFinder(c.ContainerIDCGroupMatchers)
		if err != nil {
			return nil, err
		}
	}

	return &containerHelper{
		fs:                cgroups.OSFileSystem{},
		containerIDFinder: containerIDFinder,
	}, nil
}

type containerHelper struct {
	containerIDFinder cgroup.ContainerIDFinder
	fs                cgroups.FileSystem
}

func (h *containerHelper) getContainerID(pID int32, log hclog.Logger) (string, error) {
	path := fmt.Sprintf("/proc/%v/cgroup", pID)

	filepath.Walk("/proc", func(name string, info os.FileInfo, err error) error {
		log.Info("-- name", "isdir", info.IsDir())
		return nil
	})
	// TEST CODE!!!!
	f, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	log.Info(fmt.Sprintf("---- FILE CONTENT: \n%v\n", string(f)))

	// end TEST CODE!!!!

	cgroupList, err := cgroups.GetCgroups(pID, h.fs)
	if err != nil {
		return "", err
	}
	log.Info("****** before filtering")
	for _, cgroup := range cgroupList {
		log.Info("********* cgroupEach", "controllerLIst", cgroup.ControllerList, "groupPath", cgroup.GroupPath, "HierarchyID", cgroup.HierarchyID)
	}

	log.Info("------ Get containerID", "pid", pID)
	return getContainerIDFromCGroups(h.containerIDFinder, cgroupList, log)
}

func getDockerHost(c *dockerPluginConfig) string {
	return c.DockerSocketPath
}

// getContainerIDFromCGroups returns the container ID from a set of cgroups
// using the given finder. The container ID found on each cgroup path (if any)
// must be consistent. If no container ID is found among the cgroups, i.e.,
// this isn't a docker workload, the function returns an empty string. If more
// than one container ID is found, or the "found" container ID is blank, the
// function will fail.
func getContainerIDFromCGroups(finder cgroup.ContainerIDFinder, cgroups []cgroups.Cgroup, log hclog.Logger) (string, error) {
	var hasDockerEntries bool
	var containerID string
	for _, cgroup := range cgroups {
		log.Info("-------- cgroupEach", "controllerLIst", cgroup.ControllerList, "groupPath", cgroup.GroupPath, "HierarchyID", cgroup.HierarchyID)
		log.Info(fmt.Sprintf("------ cgroup:   %q\n", cgroup.GroupPath))
		candidate, ok := finder.FindContainerID(cgroup.GroupPath)
		if !ok {
			continue
		}

		log.Info(fmt.Sprintf("------ candidate: %q\n", candidate))
		hasDockerEntries = true

		switch {
		case containerID == "":
			// This is the first container ID found so far.
			containerID = candidate
		case containerID != candidate:
			// More than one container ID found in the cgroups.
			return "", fmt.Errorf("workloadattestor/docker: multiple container IDs found in cgroups (%s, %s)",
				containerID, candidate)
		}
	}

	switch {
	case !hasDockerEntries:
		// Not a docker workload. Since it is expected that non-docker workloads will call the
		// workload API, it is fine to return a response without any selectors.
		return "", nil
	case containerID == "":
		// The "finder" found a container ID, but it was blank. This is a
		// defensive measure against bad matcher patterns and shouldn't
		// be possible with the default finder.
		return "", errors.New("workloadattestor/docker: a pattern matched, but no container id was found")
	default:
		return containerID, nil
	}
}

type defaultContainerIDFinder struct{}

// FindContainerID returns the container ID in the given cgroup path. The cgroup
// path must have the whole word "docker" at some point in the path followed
// at some point by a 64 hex-character container ID. If the cgroup path does
// not match the above description, the method returns false.
func (f *defaultContainerIDFinder) FindContainerID(cgroupPath string) (string, bool) {
	m := dockerCGroupRE.FindStringSubmatch(cgroupPath)
	if m != nil {
		return m[1], true
	}
	return "", false
}

// dockerCGroupRE matches cgroup paths that have the following properties.
// 1) `\bdocker\b` the whole word docker
// 2) `.+` followed by one or more characters (which will start on a word boundary due to #1)
// 3) `\b([[:xdigit:]][64])\b` followed by a 64 hex-character container id on word boundary
//
// The "docker" prefix and 64-hex character container id can be anywhere in the path. The only
// requirement is that the docker prefix comes before the id.
var dockerCGroupRE = regexp.MustCompile(`\bdocker\b.+\b([[:xdigit:]]{64})\b`)
