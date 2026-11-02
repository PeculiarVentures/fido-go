//go:build hid_diagnostics

package hid

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/diagnostics"
	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/driver"
)

var diagnosticEpoch atomic.Uint64

type diagnosticDevice struct {
	endpoint                  driver.Endpoint
	readEntered, writeEntered chan struct{}
	readRelease, writeRelease chan struct{}
	input                     chan driver.Report
	readOnce, writeOnce       sync.Once
	closeCount                atomic.Uint64
	held                      bool
}

func newDiagnosticDevice(id string, held bool) *diagnosticDevice {
	return &diagnosticDevice{endpoint: driver.Endpoint{ID: id}, readEntered: make(chan struct{}), writeEntered: make(chan struct{}), readRelease: make(chan struct{}), writeRelease: make(chan struct{}), input: make(chan driver.Report, 1), held: held}
}
func (device *diagnosticDevice) Endpoint() driver.Endpoint { return device.endpoint }
func (device *diagnosticDevice) Layout() driver.Layout {
	return driver.Layout{Input: driver.ReportSpec{Size: 8}, Output: driver.ReportSpec{Size: 8}}
}
func (device *diagnosticDevice) Read(wait time.Duration) (driver.Report, error) {
	device.readOnce.Do(func() { close(device.readEntered) })
	if device.held {
		<-device.readRelease
		// This old epoch's late input must be discarded during retirement.
		return driver.Report{Data: []byte{1, 2, 3, 4, 5, 6, 7, 8}}, nil
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case report := <-device.input:
		return report, nil
	case <-timer.C:
		return driver.Report{}, &driver.Error{Kind: driver.KindTimeout}
	}
}
func (device *diagnosticDevice) Write(driver.Report) (driver.WriteResult, error) {
	device.writeOnce.Do(func() { close(device.writeEntered) })
	if device.held {
		<-device.writeRelease
	}
	return driver.WriteResult{Outcome: driver.OutcomeCompleted}, nil
}
func (device *diagnosticDevice) Close() error { device.closeCount.Add(1); return nil }

func waitDiagnosticSignal(ctx context.Context, signal <-chan struct{}) error {
	select {
	case <-signal:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func closeDiagnosticGate(gate chan struct{}) {
	select {
	case <-gate:
	default:
		close(gate)
	}
}

func lifecycleDiagnosticScenario() diagnostics.Scenario {
	return diagnostics.Scenario{ID: "lifecycle.blocked-read-write", Requirements: []string{"go-lifecycle"}, Timeout: 3 * time.Second, Run: func(ctx context.Context, scope *diagnostics.Scope) error {
		id := fmt.Sprintf("diagnostics-epoch-%d", diagnosticEpoch.Add(1))
		old := newDiagnosticDevice(id, true)
		backend := &Native{open: func(driver.Endpoint) (driver.Device, error) { return old, nil }}
		conn, err := backend.Open(ctx, Endpoint{ID: EndpointID(id)})
		if err != nil {
			return err
		}
		scope.Defer(func(cleanup context.Context) error {
			closeDiagnosticGate(old.readRelease)
			closeDiagnosticGate(old.writeRelease)
			return conn.Close(cleanup)
		})
		if err := waitDiagnosticSignal(ctx, old.readEntered); err != nil {
			return err
		}
		scope.Fact("read_entered", true)
		readCtx, cancelRead := context.WithCancel(ctx)
		defer cancelRead()
		readDone := make(chan error, 1)
		go func() { _, err := conn.Read(readCtx, 0); readDone <- err }()
		actual := conn.(*connection)
		for {
			actual.mu.Lock()
			admitted := actual.readBusy
			actual.mu.Unlock()
			if admitted {
				break
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			runtime.Gosched()
		}
		scope.Fact("public_read_admitted", true)
		writeCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		type writeResult struct {
			result WriteResult
			err    error
		}
		writeDone := make(chan writeResult, 1)
		go func() {
			result, err := conn.Write(writeCtx, Report{Data: make([]byte, 8)})
			writeDone <- writeResult{result, err}
		}()
		if err := waitDiagnosticSignal(ctx, old.writeEntered); err != nil {
			return err
		}
		scope.Fact("write_entered", true)
		// Revoke both admitted callers under the shared state mutex, so neither
		// operation can observe the other's retirement before its own context.
		actual.mu.Lock()
		cancelRead()
		cancel()
		actual.mu.Unlock()
		select {
		case err := <-readDone:
			if !errors.Is(err, context.Canceled) {
				return errors.New("blocked admitted read lost cancellation")
			}
		case <-ctx.Done():
			return ctx.Err()
		}
		scope.Fact("read_cancellation_returned_before_completion", true)
		var written writeResult
		select {
		case written = <-writeDone:
		case <-ctx.Done():
			return ctx.Err()
		}
		if !errors.Is(written.err, context.Canceled) || written.result.Outcome != OutcomeUnknown {
			return errors.New("admitted blocked write cancellation lost context or unknown outcome")
		}
		scope.Fact("cancellation_returned_before_completion", true)
		canceled, cancelClose := context.WithCancel(ctx)
		cancelClose()
		if err := conn.Close(canceled); !errors.Is(err, context.Canceled) {
			return errors.New("blocked cleanup did not preserve close cancellation")
		}
		if old.closeCount.Load() != 0 {
			return errors.New("native handle closed before blocked calls completed")
		}
		scope.Fact("close_wait_bounded", true)
		scope.Fact("cleanup_deferred_until_completion", true)
		if _, err := backend.Open(ctx, Endpoint{ID: EndpointID(id)}); !errors.Is(err, ErrBusy) {
			return errors.New("retiring endpoint lease was reused")
		}
		scope.Fact("retiring_endpoint_excluded", true)
		closeDiagnosticGate(old.readRelease)
		closeDiagnosticGate(old.writeRelease)
		if err := conn.Close(ctx); err != nil {
			return err
		}
		if err := conn.Close(ctx); err != nil {
			return err
		}
		if old.closeCount.Load() != 1 {
			return errors.New("native cleanup was not exactly once")
		}
		scope.Counter("old_device_close_count", old.closeCount.Load())
		scope.Fact("repeated_close_shared_cleanup", true)
		fresh := newDiagnosticDevice(id, false)
		freshBackend := &Native{open: func(driver.Endpoint) (driver.Device, error) { return fresh, nil }}
		next, err := freshBackend.Open(ctx, Endpoint{ID: EndpointID(id)})
		if err != nil {
			return err
		}
		scope.Defer(next.Close)
		if _, err := next.Read(ctx, time.Millisecond); !errors.Is(err, ErrTimeout) {
			return errors.New("late old input reached fresh connection")
		}
		scope.Fact("late_input_isolated", true)
		if result, err := next.Write(ctx, Report{Data: make([]byte, 8)}); err != nil || result.Outcome != OutcomeCompleted {
			return errors.New("fresh connection did not remain usable")
		}
		scope.Fact("fresh_connection_usable", true)
		return nil
	}}
}
