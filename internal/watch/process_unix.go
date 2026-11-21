//go:build !windows

package watch

import (
	"os/exec"
	"syscall"
)

func startHook(cmd *exec.Cmd) (func(), error) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	kill := func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.Cancel = kill
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return func() { _ = kill() }, nil
}
