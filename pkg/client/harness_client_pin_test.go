//go:build hid_diagnostics

package client_test

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/PeculiarVentures/fido-go/internal/diagnostics"
)

func runClientDiagnostic(ctx context.Context, scope *diagnostics.Scope, options clientDiagnosticOptions, id string) (runErr error) {
	state, err := newClientDiagnosticState(scope, options)
	if err != nil {
		return err
	}
	defer func() { runErr = state.failure("client diagnostic scenario failed", runErr) }()
	switch id {
	case "client.info-pin-status":
		return state.infoStatus(ctx)
	case "client.credential-lifecycle":
		return state.credentialScenario(ctx, false)
	case "client.credential-persistence":
		return state.credentialScenario(ctx, true)
	case "client.pin-set":
		return state.setPIN(ctx)
	case "client.pin-change":
		return state.changePIN(ctx)
	case "client.reset":
		return state.reset(ctx)
	default:
		return errors.New("unknown client diagnostic scenario")
	}
}
func (state *clientDiagnosticState) infoStatus(ctx context.Context) error {
	session, err := state.fresh(ctx)
	if err != nil {
		return err
	}
	if _, supported := session.info.Options["clientPin"]; !supported {
		return diagnostics.SkipReason("the exact target does not support ClientPIN status")
	}
	status, err := session.ctap.PIN().Status(ctx)
	if err != nil {
		return state.failure("PIN status read failed", err)
	}
	state.scope.Fact("pin_status_read", true)
	state.scope.Fact("pin_configured", status.Configured)
	state.scope.Counter("pin_retries", status.Retries)
	state.scope.Fact("pin_power_cycle_needed", status.PowerCycleNeeded)
	state.pinKnown = true
	return nil
}
func (state *clientDiagnosticState) managementReady(ctx context.Context) error {
	session, err := state.fresh(ctx)
	if err != nil {
		return err
	}
	if !session.info.Options["credMgmt"] && !session.info.Options["credentialMgmtPreview"] {
		return diagnostics.SkipReason("credential management is required for verifiable PIN authorization and owned cleanup")
	}
	if !session.info.Options["clientPin"] {
		return diagnostics.SkipReason("this scenario requires an existing configured PIN")
	}
	state.pin, err = state.loadSecret(state.options.PINFile)
	if err != nil {
		return err
	}
	return state.verifyPIN(ctx)
}
func (state *clientDiagnosticState) setPIN(ctx context.Context) error {
	if !state.options.PINSet {
		return diagnostics.SkipReason("PIN establishment was not requested")
	}
	session, err := state.fresh(ctx)
	if err != nil {
		return err
	}
	configured, present := session.info.Options["clientPin"]
	if !present {
		return diagnostics.SkipReason("client PIN is unsupported")
	}
	if configured {
		return diagnostics.SkipReason("PIN set requires fresh Info proving no configured PIN")
	}
	if !session.info.Options["credMgmt"] && !session.info.Options["credentialMgmtPreview"] {
		return diagnostics.SkipReason("PIN verification requires credential management")
	}
	newPIN, err := state.loadSecret(state.options.NewPINFile)
	if err != nil {
		return err
	}
	state.scope.Fact("initial_pin_absent", true)
	state.scope.Counter("set_pin_facade_calls", 1)
	if err := session.ctap.PIN().Set(ctx, newPIN); err != nil {
		return state.mutationError("PIN set failed", err)
	}
	state.scope.Fact("set_pin_succeeded", true)
	state.pin = newPIN
	if err := state.verifyPIN(ctx); err != nil {
		return err
	}
	state.scope.Fact("new_pin_authorization_verified", true)
	state.scope.Fact("final_pin_configured", state.current.info.Options["clientPin"])
	return nil
}
func (state *clientDiagnosticState) changePIN(ctx context.Context) (runErr error) {
	if !state.options.PINChange {
		return diagnostics.SkipReason("PIN change was not requested")
	}
	if err := state.managementReady(ctx); err != nil {
		return err
	}
	original := state.pin
	temporary, err := state.loadSecret(state.options.TempPINFile)
	if err != nil {
		return err
	}
	if bytes.Equal(original, temporary) {
		return errors.New("temporary PIN must differ from the original PIN")
	}
	state.scope.Fact("original_pin_authorization_verified", true)
	calls := uint64(1)
	state.scope.Counter("pin_change_facade_calls", calls)
	if err := state.current.ctap.PIN().Change(ctx, original, temporary); err != nil {
		return state.mutationError("temporary PIN change failed", err)
	}
	state.pin = temporary
	state.scope.Fact("temporary_pin_change_succeeded", true)
	restored := false
	restore := func(cleanup context.Context) error {
		if restored {
			return nil
		}
		if state.unsafe() {
			return errors.New("PIN restoration stopped because authorization or mutation outcome is uncertain")
		}
		session, err := state.fresh(cleanup)
		if err != nil {
			return err
		}
		calls++
		state.scope.Counter("pin_change_facade_calls", calls)
		err = session.ctap.PIN().Change(cleanup, temporary, original)
		if err != nil {
			return state.mutationError("original PIN restoration failed", err)
		}
		state.pin = original
		if err := state.verifyPIN(cleanup); err != nil {
			return err
		}
		restored = true
		state.scope.Fact("original_pin_restored_verified", true)
		return nil
	}
	// Restore only after a confirmed temporary change. No ambiguous or bad-PIN
	// failure ever triggers another authorization guess from cleanup.
	attemptedRestore := false
	state.scope.Defer(func(cleanup context.Context) (cleanupErr error) {
		defer func() {
			if cleanupErr != nil {
				state.options.Safety.stop()
			}
		}()
		if restored {
			return nil
		}
		if attemptedRestore {
			return errors.New("original PIN restoration was not verified; no mutation retry is allowed")
		}
		attemptedRestore = true
		return restore(cleanup)
	})
	if err := state.verifyPIN(ctx); err != nil {
		return err
	}
	state.scope.Fact("temporary_pin_authorization_verified", true)
	attemptedRestore = true
	bounded, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	return restore(bounded)
}
