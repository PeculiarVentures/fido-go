//go:build hid_diagnostics && (!darwin || !cgo)

package hid

import (
	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/diagnostics"
	"testing"
)

func expectedDeterministicDiagnosticIDs() []string { return []string{"lifecycle.blocked-read-write"} }

func assertNativeDiagnosticEvidence(*testing.T, diagnostics.Report) {}
