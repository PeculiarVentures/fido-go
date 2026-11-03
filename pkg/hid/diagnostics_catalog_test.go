//go:build hid_diagnostics

package hid

import (
	"context"
	"testing"

	"github.com/PeculiarVentures/fido-go/internal/diagnostics"
)

func TestDiagnosticCatalogRequiresEvidenceForEveryScenario(t *testing.T) {
	scenarios := hidDiagnosticDefinitions()
	capabilities := make(map[string]bool)
	for i := range scenarios {
		if scenarios[i].Layer == "" || scenarios[i].Validate == nil {
			t.Fatalf("incomplete definition: %s", scenarios[i].ID)
		}
		for _, requirement := range scenarios[i].Requirements {
			capabilities[requirement] = true
		}
		// A callback returning success alone must never produce a qualifying JSON result.
		scenarios[i].Run = func(context.Context, *diagnostics.Scope) error { return nil }
	}
	report, err := diagnostics.Run(context.Background(), scenarios, diagnostics.Options{Capabilities: capabilities, EnabledModes: map[diagnostics.Mode]bool{diagnostics.Hardware: true, diagnostics.Strict: true, diagnostics.Interactive: true}})
	if err != nil {
		t.Fatal(err)
	}
	for _, result := range report.Results {
		if result.Status != diagnostics.Fail || result.Reason == "" {
			t.Errorf("empty evidence qualified: %+v", result)
		}
	}
}

func TestDiagnosticCatalogRetainsUnavailableScenarioIDs(t *testing.T) {
	t.Setenv("FIDO_HID_DIAGNOSTICS", "1")
	capabilities := hidDiagnosticCapabilities()
	for _, definition := range hidDiagnosticDefinitions() {
		unavailable := false
		for _, requirement := range definition.Requirements {
			if !capabilities[requirement] {
				unavailable = true
			}
		}
		if !unavailable {
			continue
		}
		report, err := runHIDDiagnostics(context.Background(), hidDiagnosticsOptions{Hardware: true, StrictIOKit: true, InteractiveUnplug: true, ScenarioIDs: []string{definition.ID}})
		if err != nil || len(report.Results) != 1 {
			t.Fatalf("selection %s: report=%+v err=%v", definition.ID, report, err)
		}
		if result := report.Results[0]; result.ScenarioID != definition.ID || result.Status != diagnostics.Skip || result.Reason == "" {
			t.Errorf("unavailable scenario=%+v", result)
		}
	}
}

func TestDiagnosticNativeValidatorRejectsLostOrMislabelledEvidence(t *testing.T) {
	result := diagnostics.Result{ScenarioID: "darwin.mask-blocked", Counters: map[string]uint64{diagnosticWriterGeneration: 1}, Facts: map[string]bool{
		"synthetic_call": true, "mask_restored": true, "before_sigurg_blocked": true, "after_sigurg_blocked": true,
		"native_submission_succeeded": true, "writer_joined": true, "device_closed": true,
	}}
	var validate func(diagnostics.Result) error
	for _, definition := range hidDiagnosticDefinitions() {
		if definition.ID == result.ScenarioID {
			validate = definition.Validate
			break
		}
	}
	if validate == nil {
		t.Fatal("native scenario validator is absent")
	}
	if err := validate(result); err != nil {
		t.Fatalf("valid fixture rejected: %v", err)
	}
	delete(result.Facts, "writer_joined")
	if validate(result) == nil {
		t.Fatal("missing writer cleanup evidence accepted")
	}
	result.Facts["writer_joined"] = true
	result.Facts["native_entry_confirmed"] = true
	if validate(result) == nil {
		t.Fatal("synthetic scenario claimed native entry")
	}
	result.Facts["native_entry_confirmed"] = false
	result.Counters[diagnosticWriterGeneration] = 0
	if validate(result) == nil {
		t.Fatal("missing writer generation accepted")
	}
}

func TestDiagnosticRegistrationRejectsInvalidCallbacksBeforeExecution(t *testing.T) {
	called := false
	callback := diagnosticRun{id: "check", run: func(context.Context, *diagnostics.Scope) error { called = true; return nil }}
	for _, tc := range []struct {
		name      string
		callbacks []diagnosticRun
	}{
		{"unknown", []diagnosticRun{callback, {id: "unknown", run: callback.run}}},
		{"duplicate", []diagnosticRun{callback, callback}},
		{"missing", nil},
		{"nil", []diagnosticRun{{id: "check"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			definitions := []diagnostics.Scenario{{ID: "check", Requirements: []string{"native"}}}
			bound, err := bindDiagnosticRuns(definitions, tc.callbacks, map[string]bool{"native": true})
			if err == nil || len(bound) != 0 || called {
				t.Fatalf("bound=%+v err=%v callback executed=%v", bound, err, called)
			}
		})
	}
}
