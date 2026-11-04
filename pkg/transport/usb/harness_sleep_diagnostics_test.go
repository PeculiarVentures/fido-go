//go:build hid_diagnostics

package usb_test

import (
	"context"
	"errors"
	"time"

	"github.com/PeculiarVentures/fido-go/internal/diagnostics"
	"github.com/PeculiarVentures/fido-go/internal/diagnostics/power"
	"github.com/PeculiarVentures/fido-go/pkg/hid"
	"github.com/PeculiarVentures/fido-go/pkg/transport/usb"
)

type usbSleepDiagnosticOptions struct {
	Hardware         bool
	InteractiveSleep bool
	OperatorPrompt   func(context.Context, string, int) error
}

type usbSleepPowerObserver interface {
	Arm() (uint64, error)
	WaitSleep(context.Context, uint64) (power.Snapshot, error)
	Wait(context.Context, uint64) (power.Snapshot, error)
	Snapshot() power.Snapshot
	Close() error
}

// This separate registration preserves the existing noninteractive USB checks.
// All platform builds retain both IDs; unavailable power observation is SKIP.
func usbSleepDiagnosticScenarios(raw hid.Backend, selected []string, options usbSleepDiagnosticOptions) []diagnostics.Scenario {
	selected = append([]string(nil), selected...)
	var result []diagnostics.Scenario
	for _, exchange := range []bool{false, true} {
		id := "usb.sleep-wake-idle"
		if exchange {
			id = "usb.sleep-wake-exchange"
		}
		result = append(result, diagnostics.Scenario{ID: id, Layer: "usb-session", Mode: diagnostics.Interactive, Requirements: []string{"integration-build", "native-hid", "power-events"}, Timeout: 25 * time.Minute, Validate: usbSleepEvidence(exchange), Run: func(ctx context.Context, scope *diagnostics.Scope) error {
			if !options.Hardware || !options.InteractiveSleep {
				return diagnostics.SkipReason("USB sleep/wake diagnostics were not requested")
			}
			if options.OperatorPrompt == nil {
				return diagnostics.InconclusiveReason("USB sleep/wake diagnostics require a bounded operator callback")
			}
			observer, err := power.New()
			if err != nil {
				return usbSleepFailure(scope, "USB diagnostic power observer creation failed", err)
			}
			return runUSBSleep(ctx, scope, raw, selected, options, exchange, observer)
		}})
	}
	return result
}

func runUSBSleep(ctx context.Context, scope *diagnostics.Scope, raw hid.Backend, selected []string, options usbSleepDiagnosticOptions, exchange bool, observer usbSleepPowerObserver) (runErr error) {
	defer func() { runErr = usbSleepFailure(scope, "USB sleep/wake diagnostic failed", runErr) }()
	closePower := func(context.Context) error {
		err := observer.Close()
		recordUSBSleepPower(scope, observer.Snapshot())
		return usbSleepFailure(scope, "USB power observer cleanup failed", err)
	}
	scope.Defer(closePower)
	if raw == nil {
		return errors.New("USB sleep diagnostic requires a HID backend")
	}
	decorated := newUSBSleepHIDBackend(raw)
	backend, err := usb.NewHIDBackendWithHID(decorated)
	if err != nil {
		return err
	}
	devices, err := usbDiagnosticDevices(ctx, scope, backend, selected)
	if err != nil {
		return err
	}
	scope.Counter("keys_selected", uint64(len(devices)))
	if len(devices) != 2 {
		return diagnostics.InconclusiveReason("USB sleep diagnostic requires exactly two selected keys in one power cycle")
	}
	records, err := warmUSBSleepSessions(ctx, scope, backend, decorated, devices)
	if err != nil {
		return err
	}
	scope.Fact("production_usb_api", true)
	scope.Fact("native_inflight_proven", false)
	scope.Fact("physical_identity_proven", false)
	scope.Fact("requests_not_replayed", true)
	scope.Fact("response_barrier_mode", exchange)
	scope.Fact("idle_sessions_quiescent", !exchange)
	scope.Counter("caller_workers_started", 0)
	scope.Counter("caller_workers_joined", 0)
	scope.Counter("response_barriers_entered", 0)
	var group *usbSleepCallGroup
	if exchange {
		group, err = startUSBSleepCalls(ctx, records)
		if err != nil {
			return err
		}
		scope.Counter("caller_workers_started", uint64(len(records)))
		scope.Defer(func(cleanup context.Context) error { return group.cleanup(cleanup, scope) })
		if err := group.waitHeld(ctx, scope); err != nil {
			return err
		}
	}
	generation, err := observer.Arm()
	if err != nil {
		return err
	}
	armed := observer.Snapshot()
	if !armed.Ready || !armed.Armed || armed.Synthetic || generation == 0 || generation != armed.ArmGeneration {
		return errors.New("USB power observer did not establish a real armed generation")
	}
	scope.Fact("power_observer_armed", true)
	phase := "usb-sleep-idle"
	if exchange {
		phase = "usb-sleep-exchange"
	}
	startCtx, cancelStart := context.WithTimeout(ctx, 5*time.Minute)
	scope.Counter("operator_prompts", 1)
	err = options.OperatorPrompt(startCtx, phase, len(records))
	if err == nil {
		_, err = observer.WaitSleep(startCtx, generation)
	}
	cancelStart()
	if err != nil {
		return usbSleepPowerWaitFailure(err)
	}
	wakeCtx, cancelWake := context.WithTimeout(ctx, 5*time.Minute)
	matched, err := observer.Wait(wakeCtx, generation)
	cancelWake()
	if err != nil {
		return usbSleepPowerWaitFailure(err)
	}
	if !matched.Matched || matched.ArmGeneration != generation || matched.WillSleepGeneration != generation || matched.PoweredOnGeneration != generation {
		return errors.New("USB sleep/wake notifications did not match the armed generation")
	}
	scope.Counter("sleep_cycle_count", 1)
	powerErr := closePower(ctx)
	var oldErr error
	if exchange {
		oldErr = group.finishAfterWake(ctx, scope)
	} else {
		oldErr = probeUSBSleepIdle(ctx, scope, records)
	}
	closeErr := closeUSBSleepOldSessions(scope, records)
	// Recovery discovery is always production USB discovery. All selectors are
	// resolved before any Open, reserving exact retained addresses first.
	recoveryErr := recoverUSBSleepSessions(ctx, scope, backend, decorated, records)
	return errors.Join(powerErr, oldErr, closeErr, recoveryErr)
}

func usbSleepPowerWaitFailure(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return errors.Join(diagnostics.InconclusiveReason("no qualifying actual USB diagnostic power event was observed within the phase budget"), err)
	}
	return err
}

func recordUSBSleepPower(scope *diagnostics.Scope, s power.Snapshot) {
	values := map[string]uint64{
		"power_observer_generation": s.ObserverGeneration, "power_arm_generation": s.ArmGeneration, "power_will_sleep_generation": s.WillSleepGeneration, "power_powered_on_generation": s.PoweredOnGeneration, "power_sleep_sequence": s.SleepSequence, "power_wake_sequence": s.WakeSequence,
		"power_can_sleep_events": s.CanSleepEvents, "power_sleep_events": s.SleepEvents, "power_wake_events": s.WakeEvents, "power_canceled_events": s.CanceledEvents, "power_out_of_order_events": s.OutOfOrderEvents, "power_extra_cycle_events": s.ExtraCycleEvents, "power_stale_events": s.StaleEvents, "power_ack_count": s.AckCount, "power_ack_errors": s.AckErrors,
		"power_native_code": uint64(s.NativeCode), "power_deregister_code": uint64(s.DeregisterCode), "power_service_close_code": uint64(s.ServiceCloseCode),
	}
	for name, value := range values {
		scope.Counter(name, value)
	}
	facts := map[string]bool{"power_observer_ready": s.Ready, "power_cycle_matched": s.Matched, "power_events_ordered": s.SleepSequence > 0 && s.WakeSequence > s.SleepSequence, "power_observer_closed": s.Closed, "power_observer_thread_joined": s.ThreadJoined, "power_observer_released": s.Released, "power_observer_synthetic": s.Synthetic}
	for name, value := range facts {
		scope.Fact(name, value)
	}
	for _, code := range []struct {
		op    string
		value uint32
	}{{"USB power observer", s.NativeCode}, {"USB power observer deregister", s.DeregisterCode}, {"USB power observer service close", s.ServiceCloseCode}} {
		if code.value != 0 {
			scope.Native(diagnostics.NativeError{Operation: code.op, Domain: "iokit", Code: uint64(code.value)})
		}
	}
}
