//go:build hid_diagnostics && integration && darwin && cgo

package hid

import (
	"context"
	"errors"
	"time"

	"github.com/PeculiarVentures/fido-go/internal/diagnostics"
	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/darwin"
)

type diagnosticPowerObserver interface {
	Arm() (uint64, error)
	WaitSleep(context.Context, uint64) (darwin.PowerSnapshot, error)
	Wait(context.Context, uint64) (darwin.PowerSnapshot, error)
	Snapshot() darwin.PowerSnapshot
	Close() error
}

func sleepDiagnosticCapabilities() map[string]bool { return map[string]bool{"power-events": true} }
func sleepHardwareDiagnosticRuns(options hidDiagnosticsOptions) []diagnosticRun {
	return []diagnosticRun{hardwareSleepRun(options, false), hardwareSleepRun(options, true)}
}

func hardwareSleepRun(options hidDiagnosticsOptions, exchange bool) diagnosticRun {
	id := "hardware.sleep-wake-idle"
	if exchange {
		id = "hardware.sleep-wake-exchange"
	}
	return diagnosticRun{id: id, run: func(ctx context.Context, scope *diagnostics.Scope) error {
		if !options.InteractiveSleep {
			return diagnostics.SkipReason("sleep/wake diagnostics were not requested")
		}
		if options.OperatorPrompt == nil {
			return diagnostics.InconclusiveReason("sleep/wake diagnostics require a bounded operator callback")
		}
		observer, err := darwin.NewPowerObserver()
		if err != nil {
			return operationError("create diagnostic power observer", "", err)
		}
		return runDiagnosticSleep(ctx, scope, options, exchange, New(), observer, attachHotplugCloseProbe)
	}}
}

// runDiagnosticSleep keeps all selected sessions in one OS cycle. Injected
// interfaces are test-only seams; live callbacks always create the real native
// observer and qualify its final, non-synthetic teardown snapshot.
func runDiagnosticSleep(ctx context.Context, scope *diagnostics.Scope, options hidDiagnosticsOptions, exchange bool, backend Backend, observer diagnosticPowerObserver, attach func(Conn) (hotplugCloseProbe, error)) (runErr error) {
	defer func() { runErr = diagnosticSafeError(scope, runErr) }()
	closePower := func(context.Context) error {
		err := observer.Close()
		recordFinalSleepPower(scope, observer.Snapshot())
		return diagnosticSafeError(scope, operationError("close diagnostic power observer", "", err))
	}
	scope.Defer(closePower)
	selected, err := diagnosticHardwareEndpointsWithBackend(ctx, backend, options.EndpointIDs)
	if err != nil {
		return err
	}
	scope.Counter(diagnosticKeysSelected, uint64(len(selected)))
	if len(selected) < 2 {
		return diagnostics.InconclusiveReason("sleep/wake diagnostics require at least two selected keys in the same OS cycle")
	}
	baseline, err := diagnosticHardwareEndpointsWithBackend(ctx, backend, nil)
	if err != nil {
		return err
	}
	candidates, err := sleepRecoveryCandidates(selected, baseline)
	if err != nil {
		return err
	}
	for index, candidate := range candidates {
		if candidate.ID != selected[index].ID {
			return diagnostics.InconclusiveReason("selected sleep endpoint changed before initialization")
		}
	}
	sessions, err := openSleepSessions(ctx, scope, backend, selected, attach)
	if err != nil {
		return err
	}
	scope.Fact("native_inflight_proven", false)
	scope.Fact("physical_identity_proven", false)
	scope.Fact("requests_replayed", false)
	scope.Fact("requests_not_replayed", true)
	scope.Fact("response_barrier_mode", exchange)
	scope.Fact("idle_sessions_quiescent", !exchange)
	var group *diagnosticSleepExchangeGroup
	if exchange {
		group, err = startSleepExchanges(ctx, sessions)
		if err != nil {
			return err
		}
		scope.Defer(func(cleanup context.Context) error { return group.cleanup(cleanup, scope) })
		if err := group.waitHeld(ctx, scope); err != nil {
			return err
		}
	}
	// No operator action is emitted until every selected key is initialized and
	// warmed, and (in exchange mode) every complete request is held before Read.
	generation, err := observer.Arm()
	if err != nil {
		return operationError("arm diagnostic power observer", "", err)
	}
	armed := observer.Snapshot()
	if !armed.Ready || !armed.Armed || armed.Synthetic || generation == 0 || armed.ArmGeneration != generation {
		return errors.New("power observer did not establish a real armed generation")
	}
	scope.Fact("power_observer_armed", true)
	scope.Counter("operator_prompts", 1)
	phase := "sleep-idle"
	if exchange {
		phase = "sleep-exchange"
	}
	startCtx, cancelStart := context.WithTimeout(ctx, 5*time.Minute)
	err = options.OperatorPrompt(startCtx, diagnosticOperatorAction{Phase: phase, KeyCount: len(sessions)})
	if err == nil {
		_, err = observer.WaitSleep(startCtx, generation)
	}
	cancelStart()
	if err != nil {
		return sleepPowerWaitError("observe system sleep", err)
	}
	wakeCtx, cancelWake := context.WithTimeout(ctx, 5*time.Minute)
	matched, err := observer.Wait(wakeCtx, generation)
	cancelWake()
	if err != nil {
		return sleepPowerWaitError("observe system wake", err)
	}
	if !matched.Matched || matched.ArmGeneration != generation || matched.WillSleepGeneration != generation || matched.PoweredOnGeneration != generation {
		return errors.New("system sleep/wake pair did not match the armed generation")
	}
	scope.Counter("sleep_cycle_count", 1)
	// Close before qualification and response consumption so late queued power
	// events and native teardown errors are included in the final snapshot.
	powerErr := closePower(ctx)
	var oldErr error
	if exchange {
		oldErr = group.finishAfterWake(ctx, scope)
	} else {
		oldErr = probeIdleSleepSessions(ctx, scope, sessions)
	}
	closeErr := closeSleepSessions(scope, sessions)
	// Always exercise a new discovery/open/INIT/PING per key, including when an
	// old session failed or its native Close returned an explicit error.
	recoveryErr := recoverSleepSessions(ctx, scope, backend, sessions)
	return errors.Join(powerErr, oldErr, closeErr, recoveryErr)
}

func sleepPowerWaitError(op string, err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return errors.Join(diagnostics.InconclusiveReason("no qualifying actual system power notification was observed within the phase budget"), err)
	}
	return operationError(op, "", err)
}

// All qualification facts about the observer's readiness and release come from
// its real final snapshot, never from a prompt, elapsed delay, or event fixture.
func recordFinalSleepPower(scope *diagnostics.Scope, s darwin.PowerSnapshot) {
	counters := map[string]uint64{
		"power_observer_generation": s.ObserverGeneration, "power_arm_generation": s.ArmGeneration, "power_will_sleep_generation": s.WillSleepGeneration, "power_powered_on_generation": s.PoweredOnGeneration,
		"power_sleep_sequence": s.SleepSequence, "power_wake_sequence": s.WakeSequence, "power_can_sleep_events": s.CanSleepEvents, "power_sleep_events": s.SleepEvents, "power_wake_events": s.WakeEvents,
		"power_canceled_events": s.CanceledEvents, "power_out_of_order_events": s.OutOfOrderEvents, "power_extra_cycle_events": s.ExtraCycleEvents, "power_stale_events": s.StaleEvents, "power_ack_count": s.AckCount, "power_ack_errors": s.AckErrors,
		"power_native_code": uint64(s.NativeCode), "power_deregister_code": uint64(s.DeregisterCode), "power_service_close_code": uint64(s.ServiceCloseCode),
	}
	for name, value := range counters {
		scope.Counter(name, value)
	}
	scope.Fact("power_observer_ready", s.Ready)
	scope.Fact("power_cycle_matched", s.Matched)
	scope.Fact("power_events_ordered", s.SleepSequence > 0 && s.WakeSequence > s.SleepSequence)
	scope.Fact("power_observer_closed", s.Closed)
	scope.Fact("power_observer_thread_joined", s.ThreadJoined)
	scope.Fact("power_observer_released", s.Released)
	scope.Fact("power_observer_synthetic", s.Synthetic)
	for _, code := range []struct {
		op    string
		value uint32
	}{{"power observer", s.NativeCode}, {"power observer deregister", s.DeregisterCode}, {"power observer service close", s.ServiceCloseCode}} {
		if code.value != 0 {
			scope.Native(diagnostics.NativeError{Operation: code.op, Domain: "iokit", Code: uint64(code.value)})
		}
	}
}
