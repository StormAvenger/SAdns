//go:build !windows

package execx

import "os/exec"

func hideWindow(*exec.Cmd) {}
