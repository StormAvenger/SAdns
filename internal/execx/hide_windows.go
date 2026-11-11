//go:build windows

package execx

import (
	"os/exec"
	"syscall"
)

// hideWindow stops PowerShell/route/tracert from flashing console windows.
func hideWindow(c *exec.Cmd) {
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
}
