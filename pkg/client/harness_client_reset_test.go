//go:build hid_diagnostics

package client_test

import (
	"context"
	"errors"
	"time"

	"github.com/PeculiarVentures/fido-go/internal/diagnostics"
)

// CTAP 2.2 section 6.6 requires reset to invalidate generated credentials and,
// for displayless authenticators, to arrive within ten seconds of power-up.
// This harness uses an eight-second observed-appearance budget and never retries.
func (state *clientDiagnosticState) reset(ctx context.Context) error {
	if !state.options.Reset {
		return diagnostics.SkipReason("destructive reset was not requested")
	}
	if err := state.managementReady(ctx); err != nil {
		return err
	}
	if _, err := state.prompt(ctx, "reset-confirm", nil); err != nil {
		return err
	}
	state.scope.Fact("reset_target_confirmed", true)
	owned, err := state.createOwned(ctx)
	if err != nil {
		return err
	}
	if err := owned.authenticate(ctx); err != nil {
		return err
	}
	state.scope.Fact("owned_credential_created_before_reset", true)
	if err := state.powerCycle(ctx, "reset", true); err != nil {
		return err
	}
	deadline := state.resetAppearance.Add(8 * time.Second)
	resetCtx, cancelReset := context.WithDeadline(ctx, deadline)
	session, err := state.fresh(resetCtx)
	if err != nil {
		cancelReset()
		return err
	}
	if err := resetCtx.Err(); err != nil {
		cancelReset()
		return diagnostics.InconclusiveReason("fresh client initialization exhausted the reset power-up submission window")
	}
	state.scope.Counter("reset_facade_calls", 1)
	state.scope.Fact("reset_facade_called_within_observed_window", time.Now().Before(deadline))
	// The facade is invoked within the conservative submission window, while
	// the actual touch/response wait gets its own generous bounded context. A
	// timeout or NotAllowed response is never replayed by this harness.
	cancelReset()
	commandCtx, cancelCommand := context.WithTimeout(ctx, 2*time.Minute)
	err = session.ctap.Reset(commandCtx)
	cancelCommand()
	if err != nil {
		return state.mutationError("explicit authenticator reset failed; no retry is allowed", err)
	}
	// A successful reset response owns this cleanup outcome even if later
	// readback fails: do not attempt another PIN-authenticated Delete after reset.
	owned.destroyed = true
	state.scope.Fact("reset_succeeded", true)
	state.pin = nil
	fresh, err := state.fresh(ctx)
	if err != nil {
		return err
	}
	configured, present := fresh.info.Options["clientPin"]
	if !present || configured {
		return errors.New("fresh post-reset Info did not prove the PIN was absent")
	}
	state.scope.Fact("final_pin_absent", true)
	state.pinKnown = true
	if err := owned.expectAbsent(ctx); err != nil {
		return err
	}
	return nil
}
