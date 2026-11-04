//go:build hid_diagnostics

package client_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/PeculiarVentures/fido-go/internal/diagnostics"
	"github.com/PeculiarVentures/fido-go/pkg/client"
	"github.com/PeculiarVentures/fido-go/pkg/ctap2"
	"github.com/PeculiarVentures/fido-go/pkg/hid"
	"github.com/PeculiarVentures/fido-go/pkg/transport/usb"
)

type clientDiagnosticSafety struct {
	mu      sync.Mutex
	blocked bool
}

func (safety *clientDiagnosticSafety) stop() {
	if safety != nil {
		safety.mu.Lock()
		safety.blocked = true
		safety.mu.Unlock()
	}
}
func (safety *clientDiagnosticSafety) stopped() bool {
	if safety == nil {
		return false
	}
	safety.mu.Lock()
	defer safety.mu.Unlock()
	return safety.blocked
}
func (state *clientDiagnosticState) unsafe() bool {
	return state.authBlocked || state.mutationUncertain || state.enrollmentSuspended
}

type clientDiagnosticState struct {
	enrollmentSuspended  bool
	suppressTouchMarkers bool
	scope                *diagnostics.Scope
	options              clientDiagnosticOptions
	locator              client.Locator
	selector             string
	pin                  client.Secret
	secrets              []client.Secret
	current              *clientDiagnosticSession
	sessions             []*clientDiagnosticSession
	authBlocked          bool
	pinKnown             bool
	mutationUncertain    bool
	resetAppearance      time.Time
}
type clientDiagnosticSession struct {
	state        *clientDiagnosticState
	sdk          client.Client
	ctap         client.CTAP2Client
	info         *client.AuthenticatorInfo
	closeFailure error
	closed       bool
}

func newClientDiagnosticState(scope *diagnostics.Scope, options clientDiagnosticOptions) (*clientDiagnosticState, error) {
	if options.Safety.stopped() {
		return nil, diagnostics.SkipReason("client invocation stopped after uncertain mutation or PIN authorization failure")
	}
	if options.Endpoint == "" || strings.Contains(options.Endpoint, ",") {
		return nil, errors.New("client diagnostics require exactly one explicit endpoint selector")
	}
	locator := options.Locator
	if locator == nil {
		var err error
		locator, err = client.NewDefaultLocator(client.WithUSB(true), client.WithNFC(false))
		if err != nil {
			return nil, errors.New("default client locator construction failed")
		}
	}
	state := &clientDiagnosticState{scope: scope, options: options, locator: locator, selector: options.Endpoint}
	scope.Counter("targets_selected", 1)
	scope.Fact("exact_selector_required", true)
	scope.Fact("physical_identity_proven", false)
	scope.Fact("harness_replayed_mutation", false)
	scope.Defer(func(cleanup context.Context) error {
		// Cleanup callbacks are snapshotted by the runner. Recovery/restore can
		// open another SDK during cleanup, so this final owner explicitly closes
		// every remaining handle before aggregation and secret wiping.
		for _, session := range state.sessions {
			if !session.closed {
				_ = session.close(cleanup)
			}
		}
		all := true
		for _, session := range state.sessions {
			all = all && session.closed && session.closeFailure == nil
		}
		scope.Fact("all_sdk_closed", all)
		closed := uint64(0)
		for _, session := range state.sessions {
			if session.closed && session.closeFailure == nil {
				closed++
			}
		}
		scope.Counter("sdk_closed", closed)
		scope.Fact("final_pin_state_known", state.pinKnown && !state.authBlocked && !state.mutationUncertain && !state.enrollmentSuspended)
		scope.Fact("stopped_after_pin_failure", state.authBlocked)
		scope.Fact("mutation_outcome_uncertain", state.mutationUncertain)
		for _, secret := range state.secrets {
			secret.Wipe()
		}
		scope.Fact("secrets_wiped", true)
		if !all {
			state.options.Safety.stop()
			return errors.New("client diagnostic SDK cleanup was not fully successful")
		}
		return nil
	})
	return state, nil
}
func (state *clientDiagnosticState) loadSecret(path string) (client.Secret, error) {
	secret, err := readClientDiagnosticSecret(path)
	if err != nil {
		return nil, err
	}
	state.secrets = append(state.secrets, secret)
	return secret, nil
}

func (state *clientDiagnosticState) fresh(ctx context.Context) (*clientDiagnosticSession, error) {
	if state.enrollmentSuspended {
		return nil, diagnostics.InconclusiveReason("exact target enrollment is suspended until explicit replug acknowledgment")
	}
	if state.current != nil {
		if err := state.current.close(ctx); err != nil {
			return nil, err
		}
		state.current = nil
	}
	devices, err := state.locator.List(ctx)
	if err != nil {
		return nil, state.failure("client discovery failed", err)
	}
	found := false
	seen := make(map[string]bool)
	for _, device := range devices {
		if device.ID == "" || seen[device.ID] {
			return nil, errors.New("client inventory contains invalid addresses")
		}
		seen[device.ID] = true
		if device.ID == state.selector {
			found = true
		}
	}
	if !found {
		return nil, diagnostics.InconclusiveReason("the explicitly enrolled client endpoint is absent")
	}
	sdk, err := state.locator.Open(ctx, state.selector, client.WithDefaultRawInvokers(), client.WithInteraction(state))
	if err != nil {
		return nil, state.failure("exact client open failed", err)
	}
	session := &clientDiagnosticSession{state: state, sdk: sdk}
	state.sessions = append(state.sessions, session)
	state.scope.Counter("sdk_opened", uint64(len(state.sessions)))
	state.current = session
	state.scope.Defer(session.close)
	session.ctap, err = sdk.CTAP2(ctx)
	if err != nil {
		var unavailable *client.CTAP2UnavailableError
		if errors.As(err, &unavailable) {
			return nil, diagnostics.SkipReason("the exact target does not support CTAP2")
		}
		return nil, state.failure("CTAP2 capability discovery failed", err)
	}
	session.info, err = session.ctap.Info(ctx)
	if err != nil {
		return nil, state.failure("fresh authenticator info failed", err)
	}
	state.scope.Fact("fresh_info_read", true)
	if _, present := session.info.Options["clientPin"]; present {
		state.pinKnown = true
		state.scope.Fact("pin_configured", session.info.Options["clientPin"])
	}
	return session, nil
}
func (session *clientDiagnosticSession) close(ctx context.Context) error {
	closer, ok := session.sdk.(client.ContextCloser)
	if !ok {
		return errors.New("client diagnostic SDK lacks context-aware cleanup")
	}
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	err := closer.CloseContext(bounded)
	if err != nil && session.closeFailure == nil {
		session.closeFailure = err
		session.state.options.Safety.stop()
	}
	session.closed = err == nil
	return session.state.failure("client SDK close failed", session.closeFailure)
}
func (state *clientDiagnosticState) OnInteraction(_ context.Context, event client.InteractionEvent) {
	if state.suppressTouchMarkers || event.Kind != client.InteractionAwaitingUserPresence || state.options.Output == nil {
		return
	}
	op := "operation"
	switch event.Operation {
	case "register", "authenticate", "reset":
		op = event.Operation
	}
	_, _ = fmt.Fprintf(state.options.Output, "CLIENT_INTERACTION operation=%s kind=touch\n", op)
}
func (state *clientDiagnosticState) RequestPIN(context.Context, client.PINRequest) (client.Secret, error) {
	if state.unsafe() {
		return nil, errors.New("PIN authentication halted after a failure")
	}
	if state.pin.Empty() {
		return nil, client.ErrPINRequired
	}
	return state.pin, nil
}

func (state *clientDiagnosticState) failure(message string, err error) error {
	if err == nil {
		return nil
	}
	safe := []error{errors.New(message)}
	var status *ctap2.Error
	if errors.As(err, &status) {
		state.scope.Counter("last_ctap_status", uint64(status.Code))
		state.scope.Fact("last_ctap_status_present", true)
		safe = append(safe, &ctap2.Error{Code: status.Code})
		if status.Code >= 0x31 && status.Code <= 0x34 {
			state.authBlocked = true
			state.options.Safety.stop()
			state.pinKnown = false
		}
	}
	for _, kind := range []error{context.Canceled, context.DeadlineExceeded, hid.ErrClosed, hid.ErrRemoved, hid.ErrPermission, hid.ErrBusy, hid.ErrUnsupported, hid.ErrIO, hid.ErrResourceLimit} {
		if errors.Is(err, kind) {
			safe = append(safe, kind)
		}
	}
	var native *hid.NativeError
	if errors.As(err, &native) {
		state.scope.Native(diagnostics.NativeError{Operation: message, Domain: native.Domain, Code: native.Code})
		safe = append(safe, &hid.NativeError{Domain: native.Domain, Code: native.Code})
	}
	var exchange *usb.ExchangeError
	if errors.As(err, &exchange) {
		state.scope.Counter("last_packets_submitted", uint64(max(0, exchange.PacketsSubmitted)))
		state.scope.Counter("last_write_outcome", uint64(exchange.Outcome))
		state.scope.Fact("last_delivery_ambiguous", exchange.Ambiguous)
	}
	if disposition, ok := diagnostics.Disposition(err); ok {
		if disposition == diagnostics.Inconclusive {
			safe = append(safe, diagnostics.InconclusiveReason("client diagnostic evidence is incomplete"))
		} else {
			safe = append(safe, diagnostics.SkipReason("client diagnostic prerequisite is unavailable"))
		}
	}
	return errors.Join(safe...)
}
func (state *clientDiagnosticState) mutationError(message string, err error) error {
	if err == nil {
		return nil
	}
	var status *ctap2.Error
	explicitUnknown := false
	var walk func(error)
	walk = func(cause error) {
		if cause == nil {
			return
		}
		if exchange, ok := cause.(*usb.ExchangeError); ok && (exchange.Ambiguous || exchange.Outcome == hid.OutcomeUnknown) {
			explicitUnknown = true
		}
		if many, ok := cause.(interface{ Unwrap() []error }); ok {
			for _, child := range many.Unwrap() {
				walk(child)
			}
		}
		if one, ok := cause.(interface{ Unwrap() error }); ok {
			walk(one.Unwrap())
		}
	}
	walk(err)
	if !errors.As(err, &status) || explicitUnknown {
		state.mutationUncertain = true
		state.options.Safety.stop()
		state.pinKnown = false
	}
	return state.failure(message, err)
}
func (state *clientDiagnosticState) verifyPIN(ctx context.Context) error {
	if state.unsafe() {
		return errors.New("PIN authentication halted after a failure")
	}
	if state.pin.Empty() {
		return client.ErrPINRequired
	}
	session, err := state.fresh(ctx)
	if err != nil {
		return err
	}
	if !session.info.Options["clientPin"] {
		return errors.New("PIN verification requires a configured PIN")
	}
	if !session.info.Options["credMgmt"] && !session.info.Options["credentialMgmtPreview"] {
		return diagnostics.SkipReason("explicit PIN authorization verification requires credential management")
	}
	_, err = session.ctap.Credentials().List(ctx, client.SecretPINAuthorization(state.pin))
	if err != nil {
		return state.failure("explicit PIN authorization failed", err)
	}
	state.scope.Fact("pin_authorization_verified", true)
	state.pinKnown = true
	return nil
}

var _ client.InteractionHandler = (*clientDiagnosticState)(nil)
