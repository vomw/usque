//go:build linux

package internal

import (
	"syscall"
)

// EnableSpeculationMitigationForCurrentThread attempts to apply the Linux
// PR_SET_SECCOMP speculation mitigation flag to the current thread when the
// syscall is available. This is best-effort and keeps the application
// functional on systems without the required kernel support.
func EnableSpeculationMitigationForCurrentThread() {
	// PR_SET_SPECULATION_CTRL is defined as 53 for Linux x86_64 and arm64.
	// The flag PR_SPEC_DISABLE is 4.
	// We deliberately avoid hard-failing if the kernel or syscall is unavailable.
	_, _, err := syscall.RawSyscall(syscall.SYS_PRCTL, 53, 0, 4)
	if err == 0 {
		return
	}
	_ = err
}

// EnableSpeculationMitigation is kept as a compatibility wrapper for the
// existing startup entrypoints.
func EnableSpeculationMitigation() {
	EnableSpeculationMitigationForCurrentThread()
}
