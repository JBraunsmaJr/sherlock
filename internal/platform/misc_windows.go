//go:build windows

package platform

import (
	"context"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ProcessNames returns the lower-cased executable names of running processes.
func ProcessNames() (map[string]bool, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	names := map[string]bool{}
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		names[strings.ToLower(windows.UTF16ToString(e.ExeFile[:]))] = true
	}
	return names, nil
}

// LowerPriority puts Sherlock below normal priority so games always win the CPU.
func LowerPriority() error {
	return windows.SetPriorityClass(windows.CurrentProcess(), windows.BELOW_NORMAL_PRIORITY_CLASS)
}

func hideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
}

func OpenBrowser(url string) error {
	return Command(context.Background(), "rundll32", "url.dll,FileProtocolHandler", url).Start()
}

func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// DiagCommands lists what to record about the machine's network state when an event fires.
func DiagCommands(ifName string) []DiagCommand {
	ps := func(script string) []string {
		return []string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script}
	}
	n := psQuote(ifName)
	return []DiagCommand{
		{File: "ipconfig.txt", Name: "ipconfig", Args: []string{"/all"}},
		{File: "routes.txt", Name: "route", Args: []string{"print", "-4"}},
		{File: "ip-interfaces.txt", Name: "netsh", Args: []string{"interface", "ipv4", "show", "interfaces"}},
		{File: "adapter.txt", Name: "powershell", Args: ps(
			"Get-NetAdapter -Name " + n + " | Format-List *; " +
				"Get-NetAdapterStatistics -Name " + n + " | Format-List *; " +
				"Get-NetAdapterAdvancedProperty -Name " + n + " | Format-Table DisplayName,DisplayValue -AutoSize | Out-String -Width 200")},
		// Run at the end so the driver's "link down" and "link up" entries are both in the log.
		{File: "system-events.txt", Name: "powershell", AtFinalize: true, Args: ps(
			"Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=(Get-Date).AddMinutes(-10)} -MaxEvents 300 -ErrorAction SilentlyContinue | " +
				"Format-List TimeCreated,ProviderName,Id,LevelDisplayName,Message | Out-String -Width 200")},
	}
}
