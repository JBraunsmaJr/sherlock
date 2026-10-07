//go:build linux

package platform

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// ProcessNames returns the lower-cased names of running processes.
func ProcessNames() (map[string]bool, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	names := map[string]bool{}
	for _, e := range entries {
		if e.Name()[0] < '0' || e.Name()[0] > '9' {
			continue
		}
		if b, err := os.ReadFile(filepath.Join("/proc", e.Name(), "comm")); err == nil {
			names[strings.ToLower(strings.TrimSpace(string(b)))] = true
		}
	}
	return names, nil
}

func LowerPriority() error { return syscall.Setpriority(syscall.PRIO_PROCESS, 0, 10) }

func hideWindow(*exec.Cmd) {}

func OpenBrowser(url string) error {
	return Command(context.Background(), "xdg-open", url).Start()
}

func DiagCommands(ifName string) []DiagCommand {
	return []DiagCommand{
		{File: "ip-addr.txt", Name: "ip", Args: []string{"addr"}},
		{File: "routes.txt", Name: "ip", Args: []string{"route"}},
		{File: "link-stats.txt", Name: "ip", Args: []string{"-s", "-s", "link", "show", "dev", ifName}},
		{File: "ethtool.txt", Name: "ethtool", Args: []string{ifName}},
		{File: "ethtool-stats.txt", Name: "ethtool", Args: []string{"-S", ifName}},
		{File: "kernel-log.txt", Name: "journalctl", Args: []string{"-k", "--since", "-10 min", "--no-pager"}, AtFinalize: true},
	}
}
