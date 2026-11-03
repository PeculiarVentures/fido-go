//go:build hid_diagnostics

package client_test

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/PeculiarVentures/fido-go/internal/diagnostics"
)

type clientDiagnosticDefinition struct {
	id           string
	mode         diagnostics.Mode
	timeout      time.Duration
	requirements []string
	facts        []string
	counters     map[string]uint64
	minimumOpens uint64
}

func clientDiagnosticDefinitions() []clientDiagnosticDefinition {
	return []clientDiagnosticDefinition{
		{
			id: "client.info-pin-status", mode: diagnostics.Hardware, timeout: 30 * time.Second,
			facts: []string{"pin_status_read"}, minimumOpens: 1,
		},
		{
			id: "client.credential-lifecycle", mode: diagnostics.Hardware, timeout: 8 * time.Minute,
			requirements: []string{"client.secure-input", "client.credentials", "client.pin-input"},
			facts:        []string{"credential_created", "credential_enumerated", "credential_readback_rp_match", "credential_readback_user_match", "credential_readback_rp_hash_match", "registration_verified", "assertion_signature_verified", "owned_credential_deleted", "owned_credential_invalidation_verified", "owned_cleanup_complete"},
			counters:     map[string]uint64{"make_credential_facade_calls": 1, "delete_credential_facade_calls": 1, "credential_readback_failure_kind": 0, "credential_readback_id_matches": 1}, minimumOpens: 1,
		},
		{
			id: "client.credential-persistence", mode: diagnostics.Interactive, timeout: 12 * time.Minute,
			requirements: []string{"client.secure-input", "client.credentials", "client.persistence", "client.pin-input", "client.operator"},
			facts:        []string{"credential_created", "credential_enumerated", "credential_readback_rp_match", "credential_readback_user_match", "credential_readback_rp_hash_match", "registration_verified", "assertion_signature_verified", "owned_credential_deleted", "owned_credential_invalidation_verified", "owned_cleanup_complete", "sdk_closed_before_unplug", "complete_absence_observed", "explicit_reenrollment", "credential_persisted_verified"},
			counters:     map[string]uint64{"make_credential_facade_calls": 1, "delete_credential_facade_calls": 1, "credential_readback_failure_kind": 0, "credential_readback_id_matches": 1}, minimumOpens: 2,
		},
		{
			id: "client.pin-set", mode: diagnostics.Hardware, timeout: 8 * time.Minute,
			requirements: []string{"client.secure-input", "client.pin-set", "client.new-pin-input"},
			facts:        []string{"initial_pin_absent", "set_pin_succeeded", "new_pin_authorization_verified", "final_pin_configured"},
			counters:     map[string]uint64{"set_pin_facade_calls": 1}, minimumOpens: 2,
		},
		{
			id: "client.pin-change", mode: diagnostics.Hardware, timeout: 8 * time.Minute,
			requirements: []string{"client.secure-input", "client.pin-change", "client.pin-input", "client.temp-pin-input"},
			facts:        []string{"original_pin_authorization_verified", "temporary_pin_change_succeeded", "temporary_pin_authorization_verified", "original_pin_restored_verified"},
			counters:     map[string]uint64{"pin_change_facade_calls": 2}, minimumOpens: 3,
		},
		{
			id: "client.reset", mode: diagnostics.Interactive, timeout: 12 * time.Minute,
			requirements: []string{"client.secure-input", "client.credentials", "client.reset", "client.pin-input", "client.operator"},
			facts:        []string{"reset_target_confirmed", "owned_credential_created_before_reset", "complete_absence_observed", "explicit_reenrollment", "reset_facade_called_within_observed_window", "reset_succeeded", "final_pin_absent", "owned_credential_invalidation_verified", "owned_cleanup_complete"},
			counters:     map[string]uint64{"reset_facade_calls": 1, "make_credential_facade_calls": 1}, minimumOpens: 2,
		},
	}
}

func clientDiagnosticScenarios(options clientDiagnosticOptions) ([]diagnostics.Scenario, error) {
	if options.Endpoint == "" || strings.TrimSpace(options.Endpoint) != options.Endpoint ||
		len(options.Endpoint) > 4096 || strings.ContainsAny(options.Endpoint, ",\x00\r\n\t") {
		return nil, errors.New("client diagnostics require exactly one explicit endpoint selector")
	}
	if options.Safety == nil {
		options.Safety = &clientDiagnosticSafety{}
	}
	definitions := clientDiagnosticDefinitions()
	result := make([]diagnostics.Scenario, 0, len(definitions))
	for _, definition := range definitions {
		result = append(result, diagnostics.Scenario{
			ID: definition.id, Layer: "client/ctap2", Mode: definition.mode, Timeout: definition.timeout,
			Requirements: append([]string{"client.hardware"}, definition.requirements...),
			Run: func(ctx context.Context, scope *diagnostics.Scope) (runErr error) {
				defer func() {
					if recovered := recover(); recovered != nil {
						options.Safety.stop()
						panic(recovered)
					}
					if runErr != nil {
						if status, explicit := diagnostics.Disposition(runErr); !explicit || status != diagnostics.Skip {
							options.Safety.stop()
						}
					}
				}()
				return runClientDiagnostic(ctx, scope, options, definition.id)
			},
			Validate: func(result diagnostics.Result) error {
				err := validateClientDiagnosticEvidence(definition, result)
				if err != nil {
					options.Safety.stop()
				}
				return err
			},
		})
	}
	return result, nil
}

func clientDiagnosticCapabilities(options clientDiagnosticOptions) map[string]bool {
	return map[string]bool{
		"client.hardware":       options.Hardware,
		"client.secure-input":   clientDiagnosticSecureInputAvailable(),
		"client.credentials":    options.Credentials,
		"client.persistence":    options.Persistence,
		"client.pin-set":        options.PINSet,
		"client.pin-change":     options.PINChange,
		"client.reset":          options.Reset,
		"client.pin-input":      options.PINFile != "",
		"client.new-pin-input":  options.NewPINFile != "",
		"client.temp-pin-input": options.TempPINFile != "",
		"client.operator":       options.Operator != nil,
	}
}

func validateClientDiagnosticEvidence(definition clientDiagnosticDefinition, result diagnostics.Result) error {
	if result.ScenarioID != definition.id || result.Layer != "client/ctap2" || result.Mode != definition.mode ||
		!result.Cleanup.Complete || len(result.Cleanup.Errors) != 0 || len(result.NativeErrors) != 0 {
		return errors.New("client diagnostic identity or cleanup evidence is incomplete")
	}
	for _, name := range []string{"fresh_info_read", "exact_selector_required", "all_sdk_closed", "secrets_wiped", "final_pin_state_known"} {
		if !result.Facts[name] {
			return errors.New("client diagnostic common postcondition is unproven")
		}
	}
	for _, name := range []string{"physical_identity_proven", "harness_replayed_mutation"} {
		if value, present := result.Facts[name]; !present || value {
			return errors.New("client diagnostic contains an unsupported identity or replay claim")
		}
	}
	if result.Counters["targets_selected"] != 1 || result.Counters["sdk_opened"] < definition.minimumOpens ||
		result.Counters["sdk_opened"] != result.Counters["sdk_closed"] {
		return errors.New("client diagnostic exact-target or session ownership evidence is incomplete")
	}
	for _, name := range definition.facts {
		if !result.Facts[name] {
			return errors.New("client diagnostic scenario postcondition is unproven")
		}
	}
	if result.Facts["credential_enumerated"] && result.Counters["credential_readback_rows"] < 1 {
		return errors.New("client diagnostic credential readback row count is incomplete")
	}
	for name, expected := range definition.counters {
		if value, present := result.Counters[name]; !present || value != expected {
			return errors.New("client diagnostic facade operation count is inconsistent")
		}
	}
	return nil
}
