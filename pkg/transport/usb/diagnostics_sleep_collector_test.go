//go:build hid_diagnostics

package usb_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"maps"
	"testing"
	"time"

	"github.com/PeculiarVentures/fido-go/internal/diagnostics"
	"github.com/PeculiarVentures/fido-go/internal/diagnostics/power"
	"github.com/PeculiarVentures/fido-go/pkg/hid"
)

// A synthetic observer models the native contract for collector tests only. It
// registers no power callback and never claims an actual hardware result.
type fakeUSBPowerObserver struct {
	s      power.Snapshot
	closes int
}

func (p *fakeUSBPowerObserver) Arm() (uint64, error) {
	p.s = power.Snapshot{ObserverGeneration: 1, ArmGeneration: 2, Ready: true, Armed: true}
	return 2, nil
}
func (p *fakeUSBPowerObserver) WaitSleep(_ context.Context, g uint64) (power.Snapshot, error) {
	if g != 2 {
		return p.s, errors.New("generation mismatch")
	}
	p.s.SleepEvents = 1
	p.s.WillSleepGeneration = 2
	p.s.SleepSequence = 1
	p.s.AckCount = 1
	return p.s, nil
}
func (p *fakeUSBPowerObserver) Wait(_ context.Context, g uint64) (power.Snapshot, error) {
	if g != 2 {
		return p.s, errors.New("generation mismatch")
	}
	p.s.WakeEvents = 1
	p.s.PoweredOnGeneration = 2
	p.s.WakeSequence = 2
	p.s.Matched = true
	return p.s, nil
}
func (p *fakeUSBPowerObserver) Snapshot() power.Snapshot { return p.s }
func (p *fakeUSBPowerObserver) Close() error {
	p.closes++
	p.s.Closed = true
	p.s.ThreadJoined = true
	p.s.Released = true
	return nil
}
func TestUSBSleepCollectorUsesProductionSessionsWithSyntheticReports(t *testing.T) {
	for _, exchange := range []bool{false, true} {
		t.Run(map[bool]string{false: "idle", true: "exchange"}[exchange], func(t *testing.T) {
			raw := &diagnosticEchoBackend{}
			for _, id := range []hid.EndpointID{"private-first", "private-second"} {
				e := usbSleepTestEndpoint(id)
				raw.endpoints = append(raw.endpoints, e)
			}
			observer := &fakeUSBPowerObserver{}
			prompts := 0
			opts := usbSleepDiagnosticOptions{Hardware: true, InteractiveSleep: true, OperatorPrompt: func(_ context.Context, phase string, keys int) error {
				prompts++
				want := "usb-sleep-idle"
				if exchange {
					want = "usb-sleep-exchange"
				}
				if phase != want || keys != 2 {
					return errors.New("wrong prompt")
				}
				return nil
			}}
			scenario := diagnostics.Scenario{ID: "synthetic-fixture", Timeout: 5 * time.Second, Run: func(ctx context.Context, s *diagnostics.Scope) error {
				return runUSBSleep(ctx, s, raw, nil, opts, exchange, observer)
			}, Validate: usbSleepEvidence(exchange)}
			report, err := diagnostics.Run(context.Background(), []diagnostics.Scenario{scenario}, diagnostics.Options{})
			if err != nil || len(report.Results) != 1 || report.Results[0].Status != diagnostics.Pass || !report.Results[0].Cleanup.Complete || prompts != 1 {
				t.Fatalf("collector status=%+v err=%v prompts=%d", report.Results, err, prompts)
			}
			if len(raw.opened) != 4 {
				t.Fatalf("production session opens=%d", len(raw.opened))
			}
			for _, conn := range raw.opened {
				if conn.initializations.Load() != 1 || conn.closes.Load() != 1 {
					t.Errorf("INIT=%d close=%d", conn.initializations.Load(), conn.closes.Load())
				}
			}
			data, err := json.Marshal(report)
			if err != nil || bytes.Contains(data, []byte("private-first")) || bytes.Contains(data, []byte("private-second")) {
				t.Fatal("synthetic report leaked endpoint selector")
			}
		})
	}
}

func TestUSBSleepCollectorRejectsCorruptEchoButStillRecoversAndCleansUp(t *testing.T) {
	raw := &diagnosticEchoBackend{corrupt: true}
	for _, id := range []hid.EndpointID{"private-first", "private-second"} {
		raw.endpoints = append(raw.endpoints, usbSleepTestEndpoint(id))
	}
	observer := &fakeUSBPowerObserver{}
	opts := usbSleepDiagnosticOptions{Hardware: true, InteractiveSleep: true, OperatorPrompt: func(context.Context, string, int) error { return nil }}
	scenario := diagnostics.Scenario{ID: "corrupt-fixture", Timeout: 5 * time.Second, Run: func(ctx context.Context, s *diagnostics.Scope) error {
		return runUSBSleep(ctx, s, raw, nil, opts, true, observer)
	}, Validate: usbSleepEvidence(true)}
	report, err := diagnostics.Run(context.Background(), []diagnostics.Scenario{scenario}, diagnostics.Options{})
	if err != nil || len(report.Results) != 1 {
		t.Fatalf("run=%v", err)
	}
	r := report.Results[0]
	if r.Status != diagnostics.Fail || !r.Cleanup.Complete || !r.Facts["all_fresh_recoveries_ping_verified"] || len(raw.opened) != 4 {
		t.Fatalf("corrupt echo masked or cleanup skipped: %+v opens=%d", r, len(raw.opened))
	}
	for _, conn := range raw.opened {
		if conn.closes.Load() != 1 {
			t.Errorf("close count=%d", conn.closes.Load())
		}
	}
}

func TestUSBSleepEvidenceRejectsMissingOrContradictoryObservations(t *testing.T) {
	for _, exchange := range []bool{false, true} {
		t.Run(map[bool]string{false: "idle", true: "exchange"}[exchange], func(t *testing.T) {
			raw := &diagnosticEchoBackend{}
			for _, id := range []hid.EndpointID{"fixture-a", "fixture-b"} {
				raw.endpoints = append(raw.endpoints, usbSleepTestEndpoint(id))
			}
			observer := &fakeUSBPowerObserver{}
			opts := usbSleepDiagnosticOptions{Hardware: true, InteractiveSleep: true, OperatorPrompt: func(context.Context, string, int) error { return nil }}
			scenario := diagnostics.Scenario{ID: "fixture", Timeout: 5 * time.Second, Run: func(ctx context.Context, s *diagnostics.Scope) error {
				return runUSBSleep(ctx, s, raw, nil, opts, exchange, observer)
			}, Validate: usbSleepEvidence(exchange)}
			report, err := diagnostics.Run(context.Background(), []diagnostics.Scenario{scenario}, diagnostics.Options{})
			if err != nil || len(report.Results) != 1 || report.Results[0].Status != diagnostics.Pass {
				t.Fatalf("fixture: %+v %v", report.Results, err)
			}
			base := report.Results[0]
			validate := usbSleepEvidence(exchange)
			for _, mutate := range []func(*diagnostics.Result){func(r *diagnostics.Result) { delete(r.Facts, "power_observer_thread_joined") }, func(r *diagnostics.Result) { r.Facts["power_observer_synthetic"] = true }, func(r *diagnostics.Result) { r.Counters["power_powered_on_generation"]++ }, func(r *diagnostics.Result) { r.Counters["power_ack_errors"] = 1 }, func(r *diagnostics.Result) { r.Facts["native_inflight_proven"] = true }, func(r *diagnostics.Result) { r.Facts["physical_identity_proven"] = true }, func(r *diagnostics.Result) { delete(r.Facts, "key_2_fresh_init_ping_verified") }, func(r *diagnostics.Result) { r.Facts["key_2_old_error_recorded"] = true }, func(r *diagnostics.Result) { r.Facts["key_1_old_close_error_recorded"] = true }, func(r *diagnostics.Result) { r.Counters["key_1_fresh_probe_attempts"] = 2 }, func(r *diagnostics.Result) { r.Counters["key_1_old_packets_submitted"]++ }, func(r *diagnostics.Result) { r.Facts["response_barrier_mode"] = !exchange }, func(r *diagnostics.Result) {
				if exchange {
					r.Counters["key_1_confirmed_writes_before_prompt"] = 17
				} else {
					r.Counters["caller_workers_started"] = 1
				}
			}} {
				r := base
				r.Facts = maps.Clone(base.Facts)
				r.Counters = maps.Clone(base.Counters)
				mutate(&r)
				if validate(r) == nil {
					t.Error("invalid USB sleep evidence accepted")
				}
			}
		})
	}
}

func TestUSBSleepScenariosRequireTheirOwnOptIn(t *testing.T) {
	raw := &diagnosticEchoBackend{}
	called := false
	options := usbSleepDiagnosticOptions{Hardware: true, InteractiveSleep: false, OperatorPrompt: func(context.Context, string, int) error { called = true; return nil }}
	scenarios := usbSleepDiagnosticScenarios(raw, nil, options)
	report, err := diagnostics.Run(context.Background(), scenarios, diagnostics.Options{Capabilities: map[string]bool{"integration-build": true, "native-hid": true, "power-events": true}, EnabledModes: map[diagnostics.Mode]bool{diagnostics.Interactive: true}})
	if err != nil || len(report.Results) != 2 || called || len(raw.opened) != 0 {
		t.Fatalf("opt-in isolation report=%+v err=%v", report, err)
	}
	for _, r := range report.Results {
		if r.Status != diagnostics.Skip {
			t.Errorf("unrequested sleep scenario status=%s", r.Status)
		}
	}
}
