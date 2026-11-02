//go:build hid_diagnostics && darwin && cgo

package hid

import (
	"context"
	"errors"
	"sync"
	"syscall"
	"time"

	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/darwin"
	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/diagnostics"
	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/driver"
)

func platformDiagnosticCapabilities() map[string]bool { return map[string]bool{"darwin-cgo": true} }

func platformDiagnosticScenarios(hidDiagnosticsOptions) []diagnostics.Scenario {
	return []diagnostics.Scenario{
		nativeMaskScenario("darwin.mask-unblocked", darwin.Config{BlockUnrelatedSignal: true}),
		nativeMaskScenario("darwin.mask-blocked", darwin.Config{InitialSIGURGBlocked: true, BlockUnrelatedSignal: true}),
		nativeMaskScenario("darwin.synthetic-sigurg", darwin.Config{InjectSIGURG: true, BlockUnrelatedSignal: true}),
		nativeFailureScenario("darwin.setup-mask-failure", darwin.Config{SetupError: int(syscall.EPERM), BlockUnrelatedSignal: true}),
		nativeFailureScenario("darwin.restore-mask-failure", darwin.Config{RestoreError: int(syscall.EIO), BlockUnrelatedSignal: true}),
		nativeFailureScenario("darwin.native-and-restore-failure", darwin.Config{NativeError: 0xe00002bc, RestoreError: int(syscall.EIO), BlockUnrelatedSignal: true}),
		nativeRetirementScenario(),
	}
}

func openSyntheticDiagnostic(ctx context.Context, scope *diagnostics.Scope, config darwin.Config) (Conn, *darwin.Probe, error) {
	device, probe, err := darwin.NewSynthetic(config)
	if err != nil {
		return nil, nil, err
	}
	handoff := newDiagnosticDeviceHandoff(device)
	// Probe lifetime is independent of the native device and outlives its join.
	scope.Defer(func(context.Context) error { return probe.Close() })
	scope.Defer(func(context.Context) error { return handoff.closeUntransferred() })
	backend := &Native{open: handoff.open}
	conn, err := backend.Open(ctx, publicEndpoint(device.Endpoint()))
	if err != nil {
		return nil, probe, err
	}
	scope.Defer(func(cleanup context.Context) error {
		releaseErr := probe.Release()
		err := errors.Join(releaseErr, conn.Close(cleanup))
		snapshot := probe.Snapshot()
		scope.Fact("writer_exited", snapshot.WriterExited)
		scope.Fact("writer_joined", snapshot.WriterJoined)
		scope.Fact("device_closed", snapshot.DeviceClosed)
		return err
	})
	return conn, probe, nil
}

func diagnosticReport(conn Conn) Report {
	return Report{ID: conn.Layout().Output.ID, Data: make([]byte, conn.Layout().Output.Size)}
}

func nativeMaskScenario(id string, config darwin.Config) diagnostics.Scenario {
	return diagnostics.Scenario{ID: id, Requirements: []string{"darwin-cgo"}, Timeout: 3 * time.Second, Run: func(ctx context.Context, scope *diagnostics.Scope) error {
		conn, probe, err := openSyntheticDiagnostic(ctx, scope, config)
		if err != nil {
			return err
		}
		result, err := conn.Write(ctx, diagnosticReport(conn))
		snapshot := probe.Snapshot()
		recordDarwinDiagnostic(scope, snapshot)
		if err != nil {
			return err
		}
		if result.Outcome != OutcomeCompleted || !snapshot.Completed || !snapshot.Submitted || snapshot.SetReportCalls != 1 {
			return errors.New("baseline did not complete exactly one native submission")
		}
		if snapshot.InitialMaskError != 0 || snapshot.MaskQueryError != 0 || !snapshot.MaskRestored {
			return errors.New("writer mask baseline/query/restoration evidence failed")
		}
		if snapshot.BeforeSIGURGBlocked != config.InitialSIGURGBlocked || snapshot.AfterSIGURGBlocked != config.InitialSIGURGBlocked {
			return errors.New("writer SIGURG mask differs from configured initial mask")
		}
		if !snapshot.BeforeUnrelatedBlocked || !snapshot.AfterUnrelatedBlocked || !snapshot.CriticalSIGURGBlocked {
			return errors.New("protected mask altered unrelated signal or failed to block SIGURG")
		}
		if !snapshot.Synthetic || snapshot.EntryConfirmed {
			return errors.New("synthetic scenario claimed actual IOKit entry")
		}
		scope.Fact("native_submission_succeeded", true)
		if config.InjectSIGURG {
			if snapshot.KillAttempts != 1 || snapshot.KillError != 0 || snapshot.KillGeneration != snapshot.Generation || !snapshot.PendingSIGURG {
				return errors.New("SIGURG was not proven pending on the intended writer generation")
			}
			scope.Fact("pending_inside_synthetic_call", true)
		}
		return nil
	}}
}

func nativeFailureScenario(id string, config darwin.Config) diagnostics.Scenario {
	return diagnostics.Scenario{ID: id, Requirements: []string{"darwin-cgo"}, Timeout: 3 * time.Second, Run: func(ctx context.Context, scope *diagnostics.Scope) error {
		conn, probe, err := openSyntheticDiagnostic(ctx, scope, config)
		if err != nil {
			return err
		}
		result, writeErr := conn.Write(ctx, diagnosticReport(conn))
		snapshot := probe.Snapshot()
		recordDarwinDiagnostic(scope, snapshot)
		if writeErr == nil {
			return errors.New("injected mask fault was not reported")
		}
		if config.SetupError != 0 {
			if result.Outcome != OutcomeNotSubmitted || snapshot.SetReportCalls != 0 || snapshot.Submitted || snapshot.SetupError != config.SetupError || !snapshot.MaskRestored {
				return errors.New("setup failure submitted I/O or failed to preserve the original mask")
			}
			if !diagnosticErrorCode(writeErr, "pthread", uint64(config.SetupError)) {
				return errors.New("setup native errno lost from error chain")
			}
			scope.Fact("setup_failed_not_submitted", true)
			scope.Fact("original_mask_intact", true)
		} else {
			if snapshot.SetReportCalls != 1 || snapshot.RestoreError != config.RestoreError || snapshot.MaskRestored {
				return errors.New("restore-failure evidence does not describe retained protected mask")
			}
			if !diagnosticErrorCode(writeErr, "pthread", uint64(config.RestoreError)) {
				return errors.New("restore native errno lost from error chain")
			}
			if config.NativeError == 0 {
				if result.Outcome != OutcomeCompleted || !snapshot.Completed {
					return errors.New("restore error discarded confirmed native write completion")
				}
				scope.Fact("completed_outcome_preserved", true)
			} else {
				if result.Outcome != OutcomeUnknown || snapshot.Completed || snapshot.NativeError != config.NativeError {
					return errors.New("combined native/restore fault lost delivery uncertainty")
				}
				if !diagnosticErrorCode(writeErr, "iokit", uint64(config.NativeError)) {
					return errors.New("combined fault lost original IOKit code")
				}
				scope.Fact("native_and_restore_errors_preserved", true)
			}
			scope.Fact("protected_mask_retained_after_restore_failure", snapshot.AfterSIGURGBlocked)
		}
		if _, err := conn.Write(ctx, diagnosticReport(conn)); !errors.Is(err, ErrClosed) {
			return errors.New("faulted connection admitted another write")
		}
		if probe.Snapshot().Writes != snapshot.Writes {
			return errors.New("faulted writer generation received another submission")
		}
		scope.Fact("old_connection_rejected", true)
		scope.Fact("no_generation_reuse", true)
		if err := conn.Close(ctx); err != nil {
			return err
		}
		closed := probe.Snapshot()
		scope.Fact("writer_exited", closed.WriterExited)
		scope.Fact("writer_joined", closed.WriterJoined)
		if !closed.WriterExited || !closed.WriterJoined {
			return errors.New("faulted writer was not exited and joined")
		}
		fresh, freshProbe, err := openSyntheticDiagnostic(ctx, scope, darwin.Config{})
		if err != nil {
			return err
		}
		freshResult, err := fresh.Write(ctx, diagnosticReport(fresh))
		if err != nil || freshResult.Outcome != OutcomeCompleted {
			return errors.New("fresh writer was unusable after prior fault")
		}
		if freshProbe.Snapshot().Generation == snapshot.Generation {
			return errors.New("new connection reused old writer generation")
		}
		scope.Fact("fresh_connection_usable", true)
		return nil
	}}
}

func recordDarwinDiagnostic(scope *diagnostics.Scope, s darwin.Snapshot) {
	scope.Counter("writer_generation", s.Generation)
	scope.Counter("writes", s.Writes)
	scope.Counter("set_report_calls", s.SetReportCalls)
	scope.Counter("kill_attempts", s.KillAttempts)
	scope.Counter("kill_generation", s.KillGeneration)
	scope.Counter("entry_generation", s.EntryGeneration)
	scope.Fact("synthetic_call", s.Synthetic)
	scope.Fact("native_entry_confirmed", s.EntryConfirmed)
	scope.Fact("mask_restored", s.MaskRestored)
	scope.Fact("before_sigurg_blocked", s.BeforeSIGURGBlocked)
	scope.Fact("before_unrelated_blocked", s.BeforeUnrelatedBlocked)
	scope.Fact("critical_sigurg_blocked", s.CriticalSIGURGBlocked)
	scope.Fact("pending_sigurg", s.PendingSIGURG)
	scope.Fact("after_sigurg_blocked", s.AfterSIGURGBlocked)
	scope.Fact("after_unrelated_blocked", s.AfterUnrelatedBlocked)
	scope.Fact("kill_succeeded", s.KillAttempts > 0 && s.KillError == 0)
	scope.Fact("kill_target_generation_matches", s.KillAttempts > 0 && s.KillGeneration == s.Generation)
	scope.Fact("writer_exited", s.WriterExited)
	scope.Fact("writer_joined", s.WriterJoined)
	scope.Fact("native_completed", s.Completed)
	if s.SetupError != 0 {
		scope.Native(diagnostics.NativeError{Operation: "block SIGURG", Domain: "pthread", Code: uint64(s.SetupError)})
	}
	if s.RestoreError != 0 {
		scope.Native(diagnostics.NativeError{Operation: "restore signal mask", Domain: "pthread", Code: uint64(s.RestoreError)})
	}
	if s.NativeError != 0 {
		scope.Native(diagnostics.NativeError{Operation: "SetReport", Domain: "iokit", Code: uint64(s.NativeError)})
	}
}

func diagnosticErrorCode(err error, domain string, code uint64) bool {
	if err == nil {
		return false
	}
	switch value := err.(type) {
	case *NativeError:
		if value.Domain == domain && value.Code == code {
			return true
		}
	case *driver.Error:
		if value.Domain == domain && value.Code == code {
			return true
		}
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for _, cause := range joined.Unwrap() {
			if diagnosticErrorCode(cause, domain, code) {
				return true
			}
		}
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		return diagnosticErrorCode(wrapped.Unwrap(), domain, code)
	}
	return false
}

// diagnosticDeviceHandoff gives the fixture two mutually exclusive owners:
// fallback cleanup before Open, or the supervisor after the injected hook wins.
// A canceled Open can return before its worker starts; claiming cleanup also
// prevents that late hook from returning an already-closed native device.
type diagnosticDeviceHandoff struct {
	mu     sync.Mutex
	device driver.Device
	state  diagnosticHandoffState
}

type diagnosticHandoffState uint8

const (
	diagnosticAvailable diagnosticHandoffState = iota
	diagnosticTransferred
	diagnosticCleanupClaimed
)

func newDiagnosticDeviceHandoff(device driver.Device) *diagnosticDeviceHandoff {
	return &diagnosticDeviceHandoff{device: device}
}

func (handoff *diagnosticDeviceHandoff) open(driver.Endpoint) (driver.Device, error) {
	handoff.mu.Lock()
	defer handoff.mu.Unlock()
	if handoff.state != diagnosticAvailable {
		return nil, &driver.Error{Op: "diagnostic open", Kind: driver.KindClosed, Message: "fixture device ownership is no longer available"}
	}
	handoff.state = diagnosticTransferred
	return handoff.device, nil
}

func (handoff *diagnosticDeviceHandoff) closeUntransferred() error {
	handoff.mu.Lock()
	if handoff.state != diagnosticAvailable {
		handoff.mu.Unlock()
		return nil
	}
	handoff.state = diagnosticCleanupClaimed
	device := handoff.device
	handoff.mu.Unlock()
	// No hook can publish this device after cleanup is claimed. After transfer,
	// this path is forbidden: only supervisor cleanup may close native resources.
	return device.Close()
}

func nativeRetirementScenario() diagnostics.Scenario {
	return diagnostics.Scenario{ID: "darwin.blocked-native-retirement", Requirements: []string{"darwin-cgo"}, Timeout: 3 * time.Second, Run: func(ctx context.Context, scope *diagnostics.Scope) error {
		conn, probe, err := openSyntheticDiagnostic(ctx, scope, darwin.Config{HoldNative: true})
		if err != nil {
			return err
		}
		writeCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		type outcome struct {
			result WriteResult
			err    error
		}
		done := make(chan outcome, 1)
		go func() { result, err := conn.Write(writeCtx, diagnosticReport(conn)); done <- outcome{result, err} }()
		if _, err := probe.Wait(ctx, darwin.PhaseNative); err != nil {
			return err
		}
		scope.Fact("native_barrier_entered", true)
		cancel()
		select {
		case written := <-done:
			if !errors.Is(written.err, context.Canceled) || written.result.Outcome != OutcomeUnknown {
				return errors.New("blocked native write did not return canceled unknown outcome")
			}
		case <-ctx.Done():
			return ctx.Err()
		}
		canceled, cancelClose := context.WithCancel(ctx)
		cancelClose()
		if err := conn.Close(canceled); !errors.Is(err, context.Canceled) {
			return errors.New("close did not return while native write remained held")
		}
		held := probe.Snapshot()
		if held.WriterJoined || held.DeviceClosed {
			return errors.New("held native writer was joined or freed prematurely")
		}
		scope.Fact("cleanup_deferred_until_native_completion", true)
		if err := probe.Release(); err != nil {
			return err
		}
		if err := conn.Close(ctx); err != nil {
			return err
		}
		closed := probe.Snapshot()
		recordDarwinDiagnostic(scope, closed)
		if !closed.Completed || !closed.WriterJoined || !closed.DeviceClosed {
			return errors.New("released native completion was not safely joined and closed")
		}
		scope.Fact("canceled_wait_preserved_late_native_completion", true)
		return nil
	}}
}
