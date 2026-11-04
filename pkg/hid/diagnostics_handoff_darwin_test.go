//go:build hid_diagnostics && darwin && cgo

package hid

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/PeculiarVentures/fido-go/internal/diagnostics"
	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/driver"
)

func TestDiagnosticsHandoffCleanupTimeoutLeavesSupervisorOwnership(t *testing.T) {
	d := &gatedLifecycleDevice{id: "diagnostic-handoff", readEntered: make(chan struct{}), writeEntered: make(chan struct{}), releaseRead: make(chan struct{}), releaseWrite: make(chan struct{}), closed: make(chan struct{})}
	var release sync.Once
	t.Cleanup(func() { release.Do(func() { close(d.releaseRead) }) })
	gate := newDiagnosticDeviceHandoff(d)
	backend := &Native{open: gate.open}
	var conn Conn
	report, err := diagnostics.Run(context.Background(), []diagnostics.Scenario{{ID: "handoff", Timeout: time.Second, Run: func(ctx context.Context, scope *diagnostics.Scope) error {
		scope.Defer(func(context.Context) error { return gate.closeUntransferred() })
		var e error
		conn, e = backend.Open(ctx, Endpoint{ID: EndpointID(d.id)})
		if e != nil {
			return e
		}
		scope.Defer(conn.Close)
		select {
		case <-d.readEntered:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}}}, diagnostics.Options{CleanupTimeout: 20 * time.Millisecond})
	if err != nil || len(report.Results) != 1 || report.Results[0].Status != diagnostics.Fail || report.Results[0].Cleanup.Complete {
		t.Fatalf("cleanup should time out: %+v %v", report, err)
	}
	select {
	case <-d.closed:
		t.Fatal("fallback closed device still owned by active supervisor")
	default:
	}
	if _, err := backend.Open(context.Background(), Endpoint{ID: EndpointID(d.id)}); !errors.Is(err, ErrBusy) {
		t.Fatalf("lease released during native read: %v", err)
	}
	release.Do(func() { close(d.releaseRead) })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := conn.Close(ctx); err != nil {
		t.Fatal(err)
	}
	waitLifecycleTestSignal(t, d.closed)
	if err := gate.closeUntransferred(); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestDiagnosticsHandoffLateOpenAfterFallbackNeverReturnsClosedDevice(t *testing.T) {
	d := newFake("diagnostic-late-handoff")
	gate := newDiagnosticDeviceHandoff(d)
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	type answer struct {
		device driver.Device
		err    error
	}
	late := make(chan answer, 1)
	backend := &Native{open: func(e driver.Endpoint) (driver.Device, error) {
		close(entered)
		<-release
		device, err := gate.open(e)
		late <- answer{device, err}
		return device, err
	}}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { _, err := backend.Open(ctx, Endpoint{ID: "diagnostic-late-handoff"}); result <- err }()
	waitLifecycleTestSignal(t, entered)
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("open cancellation=%v", err)
	}
	if err := gate.closeUntransferred(); err != nil {
		t.Fatal(err)
	}
	waitLifecycleTestSignal(t, d.closed)
	releaseOnce.Do(func() { close(release) })
	select {
	case a := <-late:
		var native *driver.Error
		if a.device != nil || !errors.As(a.err, &native) || native.Kind != driver.KindClosed {
			t.Fatalf("late hook returned device=%v err=%v", a.device, a.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("late hook did not finish")
	}
}
