//go:build hid_diagnostics

package client_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/PeculiarVentures/fido-go/internal/diagnostics"
	"github.com/PeculiarVentures/fido-go/pkg/client"
	"github.com/PeculiarVentures/fido-go/pkg/ctap2"
	"github.com/PeculiarVentures/fido-go/pkg/transport/usb"
)

type terraLocator struct {
	devices []client.Device
	listErr error
	opens   int
}

func TestTerraExplicitAmbiguousDeliveryOverridesJoinedStatus(t *testing.T) {
	report, err := diagnostics.Run(context.Background(), []diagnostics.Scenario{{ID: "ambiguous", Timeout: time.Second, Run: func(_ context.Context, scope *diagnostics.Scope) error {
		safety := &clientDiagnosticSafety{}
		state, e := newClientDiagnosticState(scope, clientDiagnosticOptions{Endpoint: "selected", Locator: &terraLocator{}, Safety: safety})
		if e != nil {
			return e
		}
		_ = state.mutationError("mutation", errors.Join(&ctap2.Error{Code: 0x37}, &usb.ExchangeError{Ambiguous: true}))
		if !state.mutationUncertain || !safety.stopped() {
			return errors.New("ambiguous delivery was overwritten by status")
		}
		return nil
	}}}, diagnostics.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if report.Results[0].Status != diagnostics.Pass {
		t.Fatalf("ambiguous delivery not retained: %s", report.Results[0].Reason)
	}
}

func (l *terraLocator) List(context.Context) ([]client.Device, error) { return l.devices, l.listErr }
func (l *terraLocator) Open(context.Context, string, ...client.Option) (client.Client, error) {
	l.opens++
	return nil, errors.New("unexpected open")
}

func TestTerraExactSelectorNoFallback(t *testing.T) {
	for _, tc := range []struct {
		name    string
		devices []client.Device
		listErr error
	}{
		{"absent", []client.Device{{ID: "other"}}, nil},
		{"duplicate", []client.Device{{ID: "selected"}, {ID: "selected"}}, nil},
		{"inventory error", nil, errors.New("private-selector-marker")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			loc := &terraLocator{devices: tc.devices, listErr: tc.listErr}
			report, err := diagnostics.Run(context.Background(), []diagnostics.Scenario{{ID: "test", Timeout: time.Second, Run: func(ctx context.Context, scope *diagnostics.Scope) error {
				state, e := newClientDiagnosticState(scope, clientDiagnosticOptions{Endpoint: "selected", Locator: loc})
				if e != nil {
					return e
				}
				_, e = state.fresh(ctx)
				return e
			}}}, diagnostics.Options{})
			if err != nil {
				t.Fatal(err)
			}
			if loc.opens != 0 {
				t.Fatal("opened a device without a unique exact target")
			}
			if report.Results[0].Status == diagnostics.Pass {
				t.Fatal("invalid inventory passed")
			}
			b, _ := json.Marshal(report)
			if strings.Contains(string(b), "private-selector-marker") {
				t.Fatal("inventory error leaked private selector")
			}
		})
	}
}

func TestTerraPINFailureAndMutationUncertaintyStaySticky(t *testing.T) {
	report, err := diagnostics.Run(context.Background(), []diagnostics.Scenario{{ID: "test", Timeout: time.Second, Run: func(ctx context.Context, scope *diagnostics.Scope) error {
		state, e := newClientDiagnosticState(scope, clientDiagnosticOptions{Endpoint: "selected", Locator: &terraLocator{}})
		if e != nil {
			return e
		}
		state.pin = client.Secret([]byte("123456"))
		state.pinKnown = true
		_ = state.mutationError("mutation failed", errors.New("private-selector-marker"))
		if !state.mutationUncertain || state.pinKnown {
			return errors.New("ambiguous mutation not retained")
		}
		_ = state.failure("PIN failed", &ctap2.Error{Code: 0x31})
		if _, e = state.RequestPIN(ctx, client.PINRequest{}); e == nil {
			return errors.New("PIN retry allowed after failure")
		}
		return nil
	}}}, diagnostics.Options{})
	if err != nil {
		t.Fatal(err)
	}
	r := report.Results[0]
	if r.Status != diagnostics.Pass || !r.Facts["mutation_outcome_uncertain"] || !r.Facts["stopped_after_pin_failure"] || r.Facts["final_pin_state_known"] {
		t.Fatalf("missing sticky safety facts: %+v", r)
	}
	data, _ := json.Marshal(report)
	if strings.Contains(string(data), "private-selector-marker") {
		t.Fatal("private marker leaked")
	}
}

func TestTerraFailureStopsLaterScenarioBeforeIO(t *testing.T) {
	for _, kind := range []string{"invalid-pin", "uncertain-mutation", "cleanup-failure"} {
		t.Run(kind, func(t *testing.T) {
			safety := &clientDiagnosticSafety{}
			loc := &terraLocator{}
			options := clientDiagnosticOptions{Endpoint: "selected", Locator: loc, Safety: safety}
			scenarios := []diagnostics.Scenario{
				{ID: "first", Timeout: time.Second, Run: func(_ context.Context, scope *diagnostics.Scope) error {
					state, err := newClientDiagnosticState(scope, options)
					if err != nil {
						return err
					}
					switch kind {
					case "invalid-pin":
						return state.failure("PIN authorization", &ctap2.Error{Code: 0x31})
					case "uncertain-mutation":
						return state.mutationError("mutation", errors.New("unknown delivery"))
					default:
						state.sessions = append(state.sessions, &clientDiagnosticSession{state: state, closed: true, closeFailure: errors.New("cleanup failure")})
						return nil
					}
				}},
				{ID: "later", Timeout: time.Second, Run: func(ctx context.Context, scope *diagnostics.Scope) error {
					state, err := newClientDiagnosticState(scope, options)
					if err != nil {
						return err
					}
					_, err = state.fresh(ctx)
					return err
				}},
			}
			report, err := diagnostics.Run(context.Background(), scenarios, diagnostics.Options{})
			if err != nil {
				t.Fatal(err)
			}
			if loc.opens != 0 || report.Results[1].Status != diagnostics.Skip {
				t.Fatalf("later scenario was not stopped before I/O: opens=%d status=%s", loc.opens, report.Results[1].Status)
			}
		})
	}
}

type terraPowerLocator struct{ calls, opens int }

func (l *terraPowerLocator) List(context.Context) ([]client.Device, error) {
	l.calls++
	if l.calls == 2 {
		return nil, nil
	}
	return []client.Device{{ID: "target", VendorID: 1, ProductID: 2}}, nil
}
func (l *terraPowerLocator) Open(context.Context, string, ...client.Option) (client.Client, error) {
	l.opens++
	return nil, errors.New("unexpected open")
}

func TestTerraFailedReenrollmentNeverReopensReusedAddress(t *testing.T) {
	loc := &terraPowerLocator{}
	report, err := diagnostics.Run(context.Background(), []diagnostics.Scenario{{ID: "cycle", Timeout: time.Second, Run: func(ctx context.Context, scope *diagnostics.Scope) error {
		operator := func(_ context.Context, action clientDiagnosticAction) (clientDiagnosticAck, error) {
			if action.Phase == "persistence-replug" {
				return clientDiagnosticAck{}, context.DeadlineExceeded
			}
			return clientDiagnosticAck{Phase: action.Phase, Token: action.Token, TargetID: action.TargetID, Approve: true}, nil
		}
		state, e := newClientDiagnosticState(scope, clientDiagnosticOptions{Endpoint: "target", Locator: loc, Operator: operator})
		if e != nil {
			return e
		}
		if e = state.powerCycle(ctx, "persistence", false); e == nil {
			return errors.New("failed re-enrollment accepted")
		}
		owned := &clientDiagnosticOwnedCredential{state: state, id: []byte("owned")}
		if e = owned.cleanup(ctx); e == nil {
			return errors.New("cleanup accepted a potentially substituted address")
		}
		return nil
	}}}, diagnostics.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if report.Results[0].Status != diagnostics.Pass || loc.opens != 0 {
		t.Fatalf("failed reenrollment was not isolated: status=%s opens=%d", report.Results[0].Status, loc.opens)
	}
}
