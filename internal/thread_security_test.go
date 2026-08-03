package internal

import "testing"

func TestEnableSpeculationMitigationForCurrentThreadDoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("EnableSpeculationMitigationForCurrentThread panicked: %v", r)
		}
	}()

	EnableSpeculationMitigationForCurrentThread()
}
