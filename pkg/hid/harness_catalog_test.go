//go:build hid_diagnostics

package hid

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/PeculiarVentures/fido-go/internal/diagnostics"
)

const (
	diagnosticKeysSelected     = "keys_selected"
	diagnosticKeysCompleted    = "keys_completed"
	diagnosticWriterGeneration = "writer_generation"
)

func diagnosticKeyPrefix(ordinal uint64) string { return fmt.Sprintf("key_%d_", ordinal) }

// hidDiagnosticDefinitions is the platform-independent catalog. Implementations
// bind callbacks by ID; unavailable builds retain the same IDs and prerequisites.
func hidDiagnosticDefinitions() []diagnostics.Scenario {
	native := []string{"darwin-cgo"}
	hardware := []string{"integration-build", "native-hid"}
	signal := []string{"integration-build", "darwin-cgo"}
	return []diagnostics.Scenario{
		{ID: "lifecycle.blocked-read-write", Layer: "hid", Requirements: []string{"go-lifecycle"}, Timeout: 3 * time.Second, Validate: validateLifecycleEvidence},
		{ID: "darwin.mask-unblocked", Layer: "hid-native", Requirements: native, Timeout: 3 * time.Second, Validate: nativeDiagnosticEvidence("synthetic_call", "mask_restored", "critical_sigurg_blocked", "before_unrelated_blocked", "after_unrelated_blocked", "native_submission_succeeded", "writer_joined", "device_closed")},
		{ID: "darwin.mask-blocked", Layer: "hid-native", Requirements: native, Timeout: 3 * time.Second, Validate: nativeDiagnosticEvidence("synthetic_call", "mask_restored", "before_sigurg_blocked", "after_sigurg_blocked", "native_submission_succeeded", "writer_joined", "device_closed")},
		{ID: "darwin.synthetic-sigurg", Layer: "hid-native", Requirements: native, Timeout: 3 * time.Second, Validate: nativeDiagnosticEvidence("synthetic_call", "mask_restored", "pending_inside_synthetic_call", "pending_sigurg", "kill_succeeded", "kill_target_generation_matches", "writer_joined", "device_closed")},
		{ID: "darwin.setup-mask-failure", Layer: "hid-native", Requirements: native, Timeout: 3 * time.Second, Validate: nativeDiagnosticEvidence("setup_failed_not_submitted", "original_mask_intact", "old_connection_rejected", "no_generation_reuse", "fresh_connection_usable", "writer_exited", "writer_joined")},
		{ID: "darwin.restore-mask-failure", Layer: "hid-native", Requirements: native, Timeout: 3 * time.Second, Validate: nativeDiagnosticEvidence("completed_outcome_preserved", "protected_mask_retained_after_restore_failure", "old_connection_rejected", "no_generation_reuse", "fresh_connection_usable", "writer_exited", "writer_joined")},
		{ID: "darwin.native-and-restore-failure", Layer: "hid-native", Requirements: native, Timeout: 3 * time.Second, Validate: nativeDiagnosticEvidence("native_and_restore_errors_preserved", "protected_mask_retained_after_restore_failure", "old_connection_rejected", "no_generation_reuse", "fresh_connection_usable", "writer_exited", "writer_joined")},
		{ID: "darwin.blocked-native-retirement", Layer: "hid-native", Requirements: native, Timeout: 3 * time.Second, Validate: nativeDiagnosticEvidence("native_barrier_entered", "cleanup_deferred_until_native_completion", "canceled_wait_preserved_late_native_completion", "writer_joined", "device_closed")},
		{ID: "hardware.sigurg-ping", Layer: "hid-native", Mode: diagnostics.Hardware, Requirements: signal, Timeout: 30 * time.Second, Validate: hardwareEvidence(signalEvidence(false))},
		{ID: "hardware.multiframe-ping", Layer: "hid", Mode: diagnostics.Hardware, Requirements: hardware, Timeout: 40 * time.Second, Validate: hardwareEvidence(validateMultiframeEvidence)},
		{ID: "hardware.parallel-exchange", Layer: "hid", Mode: diagnostics.Hardware, Requirements: hardware, Timeout: 30 * time.Second, Validate: hardwareEvidence(validateParallelEvidence)},
		{ID: "hardware.cancel-close", Layer: "hid", Mode: diagnostics.Hardware, Requirements: hardware, Timeout: time.Minute, Validate: hardwareEvidence(validateCancelEvidence)},
		{ID: "hardware.unplug-replug", Layer: "hid", Mode: diagnostics.Interactive, Requirements: hardware, Timeout: 25 * time.Minute, Validate: hardwareEvidence(validateHotplugEvidence)},
		{ID: "hardware.strict-iokit-entry", Layer: "hid-native", Mode: diagnostics.Strict, Requirements: signal, Timeout: 30 * time.Second, Validate: hardwareEvidence(signalEvidence(true))},
	}
}

type diagnosticRun struct {
	id  string
	run func(context.Context, *diagnostics.Scope) error
}

// bindDiagnosticRuns joins callbacks to the catalog and rejects registration
// errors before any scenario can perform I/O.
func bindDiagnosticRuns(definitions []diagnostics.Scenario, callbacks []diagnosticRun, capabilities map[string]bool) ([]diagnostics.Scenario, error) {
	byID := make(map[string]func(context.Context, *diagnostics.Scope) error, len(callbacks))
	for _, callback := range callbacks {
		if callback.run == nil || byID[callback.id] != nil {
			return nil, errors.New("invalid or duplicate HID diagnostic callback")
		}
		byID[callback.id] = callback.run
	}
	for index := range definitions {
		definition := &definitions[index]
		definition.Run = byID[definition.ID]
		delete(byID, definition.ID)
		if definition.Run != nil {
			continue
		}
		available := true
		for _, requirement := range definition.Requirements {
			available = available && capabilities[requirement]
		}
		if available {
			return nil, errors.New("available HID diagnostic has no callback")
		}
		definition.Run = func(context.Context, *diagnostics.Scope) error {
			return errors.New("diagnostic implementation unavailable")
		}
	}
	if len(byID) != 0 {
		return nil, errors.New("unknown HID diagnostic callback ID")
	}
	return definitions, nil
}

func validateLifecycleEvidence(r diagnostics.Result) error {
	var e diagnostics.Evidence
	e.RequireFacts(r, "read_entered", "public_read_admitted", "write_entered", "read_cancellation_returned_before_completion", "cancellation_returned_before_completion", "close_wait_bounded", "cleanup_deferred_until_completion", "retiring_endpoint_excluded", "repeated_close_shared_cleanup", "late_input_isolated", "fresh_connection_usable")
	if r.Counters["old_device_close_count"] != 1 {
		e.Errorf("old device cleanup was not exactly once")
	}
	return e.Err()
}

func hardwareEvidence(validate func(diagnostics.Result) error) func(diagnostics.Result) error {
	return func(r diagnostics.Result) error {
		keys := r.Counters[diagnosticKeysSelected]
		if keys == 0 || r.Counters[diagnosticKeysCompleted] != keys {
			return errors.New("selected keys did not all complete")
		}
		return validate(r)
	}
}
