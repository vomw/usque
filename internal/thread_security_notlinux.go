//go:build !linux

package internal

// EnableSpeculationMitigation is a no-op on non-Linux systems.
func EnableSpeculationMitigation() {}
