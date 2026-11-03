//go:build hid_diagnostics && integration

package hid

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"runtime"
	"time"

	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/diagnostics"
	wirehid "github.com/PeculiarVentures/fido-go/pkg/wire/hid"
)

func supplementalHardwareDiagnosticScenarios(options hidDiagnosticsOptions) []diagnostics.Scenario {
	return []diagnostics.Scenario{hardwareCancelCloseScenario(options), hardwareHotplugScenario(options)}
}

func hardwareCancelCloseScenario(options hidDiagnosticsOptions) diagnostics.Scenario {
	return diagnostics.Scenario{ID: "hardware.cancel-close", Requirements: []string{"integration-build"}, Timeout: time.Minute, Run: func(ctx context.Context, scope *diagnostics.Scope) (runErr error) {
		defer func() { runErr = diagnosticSafeError(scope, runErr) }()
		if !options.Hardware {
			return diagnostics.SkipReason("hardware diagnostics not requested")
		}
		endpoints, err := diagnosticHardwareEndpoints(ctx, options.EndpointIDs)
		if err != nil {
			return err
		}
		scope.Counter("keys_selected", uint64(len(endpoints)))
		if len(endpoints) == 0 {
			return diagnostics.InconclusiveReason("no selected USB FIDO endpoint is available")
		}
		scope.Fact("protected_before_iokit_barrier", supplementalNativeWriteAvailable())
		scope.Fact("native_write_stage_available", supplementalNativeWriteAvailable())
		scope.Fact("native_write_stage_skipped", !supplementalNativeWriteAvailable())
		scope.Fact("actual_kernel_inflight_cancellation", false)
		scope.Fact("requests_replayed", false)
		for index, endpoint := range endpoints {
			bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
			err := diagnoseHardwareCancellation(bounded, scope, endpoint, index+1)
			cancel()
			if err != nil {
				return err
			}
			scope.Counter("keys_completed", uint64(index+1))
		}
		for _, fact := range []string{"all_admitted_reads_canceled", "all_old_connections_reject_reuse", "all_bounded_closes_observed", "all_native_cleanups_completed", "all_fresh_reopens_ping_verified"} {
			scope.Fact(fact, true)
		}
		return nil
	}}
}

func diagnoseHardwareCancellation(ctx context.Context, scope *diagnostics.Scope, endpoint Endpoint, ordinal int) error {
	prefix := fmt.Sprintf("key_%d_", ordinal)
	readConn, readCID, err := openDiagnosticChannel(ctx, scope, endpoint)
	if err != nil {
		return err
	}
	readCtx, cancelRead := context.WithCancel(ctx)
	readDone := make(chan struct{})
	var readErr error
	go func() { _, readErr = readConn.Read(readCtx, 0); close(readDone) }()
	// Public cancellation never waits for native completion. Always join this
	// caller before returning, including admission/context failures.
	defer func() { cancelRead(); <-readDone }()
	if err = cancelAdmittedDiagnosticRead(ctx, readConn, readDone, cancelRead); err != nil {
		return err
	}
	scope.Fact(prefix+"read_admitted", true)
	if err = waitDiagnosticSignal(ctx, readDone); err != nil {
		return err
	}
	if !errors.Is(readErr, context.Canceled) {
		return errors.New("admitted physical read did not preserve cancellation")
	}
	scope.Fact(prefix+"read_canceled", true)
	closeCtx, cancelClose := context.WithTimeout(ctx, 250*time.Millisecond)
	started := time.Now()
	err = readConn.Close(closeCtx)
	cancelClose()
	scope.Counter(prefix+"read_close_duration_ns", uint64(time.Since(started)))
	if err != nil && !errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if err = finishPhysicalDiagnosticClose(ctx, readConn); err != nil {
		return err
	}
	scope.Fact(prefix+"read_native_cleanup", true)
	if err = assertSupplementalRetired(ctx, readConn, readCID); err != nil {
		return err
	}

	if err = diagnosePendingReadClose(ctx, scope, endpoint, prefix); err != nil {
		return err
	}
	if supplementalNativeWriteAvailable() {
		if err = diagnoseNativeWriteCancellation(ctx, scope, endpoint, ordinal); err != nil {
			return err
		}
	} else {
		scope.Fact(prefix+"native_write_stage_skipped", true)
	}

	fresh, cid, err := openDiagnosticChannel(ctx, scope, endpoint)
	if err != nil {
		return err
	}
	if err = supplementalFreshPing(ctx, fresh, cid); err != nil {
		return err
	}
	scope.Fact(prefix+"fresh_reopen_ping", true)
	return fresh.Close(ctx)
}

// cancelAdmittedDiagnosticRead observes actual admission and cancels under the
// same mutex, rather than treating an elapsed sleep as evidence of admission.
func cancelAdmittedDiagnosticRead(ctx context.Context, conn Conn, done <-chan struct{}, cancel context.CancelFunc) error {
	raw, ok := conn.(*connection)
	if !ok {
		return ErrInvalidArgument
	}
	for {
		raw.mu.Lock()
		if raw.readBusy {
			cancel()
			raw.mu.Unlock()
			return nil
		}
		retiring := raw.retiring
		raw.mu.Unlock()
		if retiring {
			return diagnostics.InconclusiveReason("physical connection retired before blocked-read admission")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-done:
			return diagnostics.InconclusiveReason("physical read completed before blocked-read admission was observed")
		default:
			runtime.Gosched()
		}
	}
}

func assertSupplementalRetired(ctx context.Context, conn Conn, cid uint32) error {
	if _, err := conn.Read(ctx, time.Millisecond); !errors.Is(err, ErrClosed) {
		return errors.New("old physical connection accepted a read after retirement")
	}
	report, err := supplementalPingReport(conn, cid)
	if err != nil {
		return err
	}
	result, err := conn.Write(ctx, report)
	if !errors.Is(err, ErrClosed) || result.Outcome != OutcomeNotSubmitted {
		return errors.New("old physical connection accepted a write after retirement")
	}
	return nil
}

func supplementalPingReport(conn Conn, cid uint32) (Report, error) {
	payload := make([]byte, 24)
	if _, err := rand.Read(payload); err != nil {
		return Report{}, err
	}
	codec, err := wirehid.NewCodec(cid, 0x81, 64)
	if err != nil {
		return Report{}, err
	}
	packets, err := codec.Fragment(payload)
	if err != nil {
		return Report{}, err
	}
	if len(packets) != 1 {
		return Report{}, errors.New("single-report cancellation probe produced multiple frames")
	}
	return Report{ID: conn.Layout().Output.ID, Data: packets[0]}, nil
}

func supplementalFreshPing(ctx context.Context, conn Conn, cid uint32) error {
	payload := make([]byte, 24)
	if _, err := rand.Read(payload); err != nil {
		return err
	}
	response, result, err := diagnosticHIDMessage(ctx, conn, cid, 0x81, payload)
	if err != nil {
		return err
	}
	if result.Outcome != OutcomeCompleted || !bytes.Equal(response, payload) {
		return errors.New("fresh physical PING did not complete with exact payload echo")
	}
	return nil
}

func finishPhysicalDiagnosticClose(ctx context.Context, conn Conn) error {
	bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return conn.Close(bounded)
}

func diagnosePendingReadClose(ctx context.Context, scope *diagnostics.Scope, endpoint Endpoint, prefix string) error {
	conn, cid, err := openDiagnosticChannel(ctx, scope, endpoint)
	if err != nil {
		return err
	}
	readCtx, cancelRead := context.WithCancel(ctx)
	done := make(chan struct{})
	var readErr error
	go func() { _, readErr = conn.Read(readCtx, 0); close(done) }()
	defer func() { cancelRead(); <-done }()
	if err = observeHotplugReadAdmission(ctx, conn, done); err != nil {
		return err
	}
	scope.Fact(prefix+"close_read_admitted", true)
	bounded, cancelClose := context.WithTimeout(ctx, 250*time.Millisecond)
	err = conn.Close(bounded)
	cancelClose()
	if err != nil && !errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if err = waitDiagnosticSignal(ctx, done); err != nil {
		return err
	}
	if !errors.Is(readErr, ErrClosed) {
		return errors.New("Close did not retire the admitted physical read")
	}
	if err = finishPhysicalDiagnosticClose(ctx, conn); err != nil {
		return err
	}
	if err = assertSupplementalRetired(ctx, conn, cid); err != nil {
		return err
	}
	scope.Fact(prefix+"close_read_completed", true)
	return nil
}
