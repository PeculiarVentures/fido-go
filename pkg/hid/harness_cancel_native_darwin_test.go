//go:build hid_diagnostics && integration && darwin && cgo

package hid

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/darwin"
	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/diagnostics"
	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/driver"
)

func supplementalNativeWriteAvailable() bool { return true }

func diagnoseNativeWriteCancellation(ctx context.Context, scope *diagnostics.Scope, endpoint Endpoint, ordinal int) error {
	prefix := fmt.Sprintf("key_%d_", ordinal)

	writeConn, writeCID, err := openDiagnosticChannel(ctx, scope, endpoint)
	if err != nil {
		return err
	}
	writeProbe, err := attachSupplementalProbe(scope, writeConn)
	if err != nil {
		return err
	}
	// This holds the real writer after masking SIGURG and before calling IOKit.
	// It proves ownership/retirement while admitted native work is held, not
	// cancellation of an actual kernel request already in flight.
	if err = writeProbe.Arm(darwin.Config{HoldNative: true}); err != nil {
		return err
	}
	report, err := supplementalPingReport(writeConn, writeCID)
	if err != nil {
		return err
	}
	writeCtx, cancelWrite := context.WithCancel(ctx)
	writeDone := make(chan struct{})
	var writeErr error
	var writeResult WriteResult
	go func() { writeResult, writeErr = writeConn.Write(writeCtx, report); close(writeDone) }()
	defer func() { cancelWrite(); _ = writeProbe.Release(); <-writeDone }()
	if _, err = writeProbe.Wait(ctx, darwin.PhaseNative); err != nil {
		return err
	}
	scope.Fact(prefix+"write_admitted", true)
	cancelWrite()
	if err = waitDiagnosticSignal(ctx, writeDone); err != nil {
		return err
	}
	if !errors.Is(writeErr, context.Canceled) || writeResult.Outcome != OutcomeUnknown {
		return errors.New("admitted physical write did not return canceled with unknown outcome")
	}
	scope.Fact(prefix+"write_canceled", true)
	closeCtx, cancelClose := context.WithTimeout(ctx, 50*time.Millisecond)
	started := time.Now()
	err = writeConn.Close(closeCtx)
	cancelClose()
	scope.Counter(prefix+"write_close_duration_ns", uint64(time.Since(started)))
	if !errors.Is(err, context.DeadlineExceeded) {
		return errors.New("Close did not honor its deadline while the protected writer was held")
	}
	scope.Fact(prefix+"close_deadline_observed", true)
	held := writeProbe.Snapshot()
	if held.WriterJoined || held.DeviceClosed || held.Completed {
		return errors.New("held protected writer completed or was freed before barrier release")
	}
	scope.Fact(prefix+"cleanup_deferred", true)
	if err = assertSupplementalRetired(ctx, writeConn, writeCID); err != nil {
		return err
	}
	if err = writeProbe.Release(); err != nil {
		return err
	}
	if err = finishSupplementalClose(ctx, writeConn, writeProbe); err != nil {
		return err
	}
	finished := writeProbe.Snapshot()
	if finished.SetReportCalls != 1 || !finished.Submitted || !finished.Completed || finished.NativeError != 0 || !finished.MaskRestored || finished.Synthetic {
		return errors.New("released physical PING did not complete exactly once with restored mask")
	}
	scope.Counter(prefix+"native_submissions", finished.SetReportCalls)
	scope.Fact(prefix+"writer_joined", finished.WriterJoined)
	scope.Fact(prefix+"device_closed", finished.DeviceClosed)

	return nil
}

func attachSupplementalProbe(scope *diagnostics.Scope, conn Conn) (*darwin.Probe, error) {
	var probe *darwin.Probe
	err := withDiagnosticDevice(conn, func(device driver.Device) error {
		var err error
		probe, err = darwin.Attach(device)
		return err
	})
	if err != nil {
		return nil, err
	}
	// Register before Arm or any potentially blocking work. This releases even
	// a barrier reached after its caller's context expired.
	scope.Defer(func(ctx context.Context) error {
		_ = probe.Release()
		err := conn.Close(ctx)
		_ = probe.Close()
		return diagnosticSafeError(scope, err)
	})
	return probe, nil
}

func finishSupplementalClose(ctx context.Context, conn Conn, probe *darwin.Probe) error {
	bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := conn.Close(bounded); err != nil {
		return err
	}
	snapshot, err := probe.Wait(bounded, darwin.PhaseWriterJoined|darwin.PhaseDeviceClosed)
	if err != nil {
		return err
	}
	if !snapshot.WriterExited || !snapshot.WriterJoined || !snapshot.DeviceClosed {
		return errors.New("physical native cleanup evidence is incomplete")
	}
	return nil
}
