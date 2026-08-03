//go:build !linux

package internal

// EnableSpeculationMitigationForCurrentThread is a no-op on non-Linux systems.
func EnableSpeculationMitigationForCurrentThread() {}

// EnableSpeculationMitigation is a compatibility wrapper for non-Linux systems.
func EnableSpeculationMitigation() {
	EnableSpeculationMitigationForCurrentThread()
}
