//go:build hid_diagnostics

package hid

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/driver"
)

// gatedLifecycleDevice lets the test hold both native directions across retirement.
type gatedLifecycleDevice struct {
	id                        string
	readEntered, writeEntered chan struct{}
	releaseRead, releaseWrite chan struct{}
	closed                    chan struct{}
	readOnce, writeOnce       sync.Once
}

func (d *gatedLifecycleDevice) Endpoint() driver.Endpoint { return driver.Endpoint{ID: d.id} }
func (d *gatedLifecycleDevice) Layout() driver.Layout {
	return driver.Layout{Input: driver.ReportSpec{Size: 2}, Output: driver.ReportSpec{Size: 2}}
}
func (d *gatedLifecycleDevice) Read(time.Duration) (driver.Report, error) {
	d.readOnce.Do(func() { close(d.readEntered) })
	<-d.releaseRead
	return driver.Report{Data: []byte{1, 2}}, nil
}
func (d *gatedLifecycleDevice) Write(driver.Report) (driver.WriteResult, error) {
	d.writeOnce.Do(func() { close(d.writeEntered) })
	<-d.releaseWrite
	return driver.WriteResult{Outcome: driver.OutcomeCompleted}, nil
}
func (d *gatedLifecycleDevice) Close() error { close(d.closed); return nil }
func waitLifecycleTestSignal(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("diagnostic barrier timed out")
	}
}
func TestDiagnosticsLifetimeCleanupWaitsForBothNativeCalls(t *testing.T) {
	d := &gatedLifecycleDevice{id: "diagnostic-lifecycle", readEntered: make(chan struct{}), writeEntered: make(chan struct{}), releaseRead: make(chan struct{}), releaseWrite: make(chan struct{}), closed: make(chan struct{})}
	var readRelease, writeRelease sync.Once
	t.Cleanup(func() {
		readRelease.Do(func() { close(d.releaseRead) })
		writeRelease.Do(func() { close(d.releaseWrite) })
	})
	n := &Native{open: func(driver.Endpoint) (driver.Device, error) { return d, nil }}
	c, err := n.Open(context.Background(), Endpoint{ID: EndpointID(d.id)})
	if err != nil {
		t.Fatal(err)
	}
	waitLifecycleTestSignal(t, d.readEntered)
	ctx, cancel := context.WithCancel(context.Background())
	writeDone := make(chan error, 1)
	go func() { _, err := c.Write(ctx, Report{Data: []byte{3, 4}}); writeDone <- err }()
	waitLifecycleTestSignal(t, d.writeEntered)
	cancel()
	if err := <-writeDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("write cancellation: %v", err)
	}
	expired, stop := context.WithCancel(context.Background())
	stop()
	if err := c.Close(expired); !errors.Is(err, context.Canceled) {
		t.Fatalf("close while active: %v", err)
	}
	if _, err := n.Open(context.Background(), Endpoint{ID: EndpointID(d.id)}); !errors.Is(err, ErrBusy) {
		t.Fatalf("retiring lease: %v", err)
	}
	readRelease.Do(func() { close(d.releaseRead) })
	select {
	case <-d.closed:
		t.Fatal("device closed while write remained active")
	default:
	}
	writeRelease.Do(func() { close(d.releaseWrite) })
	closeCtx, closeCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer closeCancel()
	if err := c.Close(closeCtx); err != nil {
		t.Fatal(err)
	}
	waitLifecycleTestSignal(t, d.closed)
	if err := c.Close(closeCtx); err != nil {
		t.Fatalf("repeated close: %v", err)
	}
}

func TestDiagnosticsLateInputCannotReachReopenedSession(t *testing.T) {
	d := &gatedLifecycleDevice{id: "diagnostic-epoch", readEntered: make(chan struct{}), writeEntered: make(chan struct{}), releaseRead: make(chan struct{}), releaseWrite: make(chan struct{}), closed: make(chan struct{})}
	var release sync.Once
	t.Cleanup(func() { release.Do(func() { close(d.releaseRead) }) })
	n := &Native{open: func(driver.Endpoint) (driver.Device, error) { return d, nil }}
	old, err := n.Open(context.Background(), Endpoint{ID: EndpointID(d.id)})
	if err != nil {
		t.Fatal(err)
	}
	waitLifecycleTestSignal(t, d.readEntered)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := old.Close(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("close while read pending: %v", err)
	}
	release.Do(func() { close(d.releaseRead) })
	ctx, done := context.WithTimeout(context.Background(), 3*time.Second)
	defer done()
	if err := old.Close(ctx); err != nil {
		t.Fatal(err)
	}
	fresh := newFake(d.id)
	other := &Native{open: func(driver.Endpoint) (driver.Device, error) { return fresh, nil }}
	current, err := other.Open(ctx, Endpoint{ID: EndpointID(d.id)})
	if err != nil {
		t.Fatal(err)
	}
	defer current.Close(ctx)
	fresh.reads <- driver.Report{ID: 1, Data: []byte{7, 8}}
	r, err := current.Read(ctx, time.Second)
	if err != nil || len(r.Data) != 2 || r.Data[0] != 7 || r.Data[1] != 8 {
		t.Fatalf("new session got late input: %+v, %v", r, err)
	}
}

type readFailureDuringWriteDevice struct {
	entered, releaseRead, releaseWrite, closed chan struct{}
}

func (d *readFailureDuringWriteDevice) Endpoint() driver.Endpoint {
	return driver.Endpoint{ID: "diagnostic-write-result"}
}
func (d *readFailureDuringWriteDevice) Layout() driver.Layout {
	return driver.Layout{Input: driver.ReportSpec{Size: 1}, Output: driver.ReportSpec{Size: 1}}
}
func (d *readFailureDuringWriteDevice) Read(time.Duration) (driver.Report, error) {
	<-d.releaseRead
	return driver.Report{}, &driver.Error{Kind: driver.KindIO, Domain: "iokit", Code: 99}
}
func (d *readFailureDuringWriteDevice) Write(driver.Report) (driver.WriteResult, error) {
	close(d.entered)
	<-d.releaseWrite
	return driver.WriteResult{Outcome: driver.OutcomeCompleted}, &driver.Error{Kind: driver.KindIO, Domain: "pthread", Code: 5}
}
func (d *readFailureDuringWriteDevice) Close() error { close(d.closed); return nil }
func TestDiagnosticsReadFailureDoesNotDiscardCompletedWriteResult(t *testing.T) {
	d := &readFailureDuringWriteDevice{entered: make(chan struct{}), releaseRead: make(chan struct{}), releaseWrite: make(chan struct{}), closed: make(chan struct{})}
	var readRelease, writeRelease sync.Once
	t.Cleanup(func() {
		readRelease.Do(func() { close(d.releaseRead) })
		writeRelease.Do(func() { close(d.releaseWrite) })
	})
	backend := &Native{open: func(driver.Endpoint) (driver.Device, error) { return d, nil }}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := backend.Open(ctx, Endpoint{ID: "diagnostic-write-result"})
	if err != nil {
		t.Fatal(err)
	}
	type answer struct {
		result WriteResult
		err    error
	}
	done := make(chan answer, 1)
	go func() { r, e := conn.Write(ctx, Report{Data: []byte{1}}); done <- answer{r, e} }()
	waitLifecycleTestSignal(t, d.entered)
	readRelease.Do(func() { close(d.releaseRead) })
	waitLifecycleTestSignal(t, conn.(*connection).retired)
	select {
	case got := <-done:
		t.Fatalf("read fault discarded pending write outcome: %+v %v", got.result, got.err)
	default:
	}
	writeRelease.Do(func() { close(d.releaseWrite) })
	select {
	case got := <-done:
		var native *NativeError
		if got.result.Outcome != OutcomeCompleted || !errors.As(got.err, &native) || native.Domain != "pthread" || native.Code != 5 {
			t.Fatalf("write outcome=%+v error=%v", got.result, got.err)
		}
	case <-ctx.Done():
		t.Fatal("write did not finish")
	}
	if err := conn.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestDiagnosticsExternalCloseKeepsAcceptedWriteUntilContextCancellation(t *testing.T) {
	d := &gatedLifecycleDevice{id: "diagnostic-external-close", readEntered: make(chan struct{}), writeEntered: make(chan struct{}), releaseRead: make(chan struct{}), releaseWrite: make(chan struct{}), closed: make(chan struct{})}
	var rr, wr sync.Once
	t.Cleanup(func() { rr.Do(func() { close(d.releaseRead) }); wr.Do(func() { close(d.releaseWrite) }) })
	n := &Native{open: func(driver.Endpoint) (driver.Device, error) { return d, nil }}
	c, err := n.Open(context.Background(), Endpoint{ID: EndpointID(d.id)})
	if err != nil {
		t.Fatal(err)
	}
	waitLifecycleTestSignal(t, d.readEntered)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type answer struct {
		r WriteResult
		e error
	}
	done := make(chan answer, 1)
	go func() { r, e := c.Write(ctx, Report{Data: []byte{1, 2}}); done <- answer{r, e} }()
	waitLifecycleTestSignal(t, d.writeEntered)
	closeCtx, stop := context.WithCancel(context.Background())
	stop()
	if err := c.Close(closeCtx); !errors.Is(err, context.Canceled) {
		t.Fatalf("bounded close=%v", err)
	}
	select {
	case <-d.closed:
		t.Fatal("close freed active native operations")
	default:
	}
	cancel()
	select {
	case a := <-done:
		if !errors.Is(a.e, context.Canceled) || a.r.Outcome != OutcomeUnknown {
			t.Fatalf("canceled accepted write=%+v %v", a.r, a.e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("canceled write did not return")
	}
	rr.Do(func() { close(d.releaseRead) })
	wr.Do(func() { close(d.releaseWrite) })
	cleanup, stopCleanup := context.WithTimeout(context.Background(), 3*time.Second)
	defer stopCleanup()
	if err := c.Close(cleanup); err != nil {
		t.Fatal(err)
	}
	waitLifecycleTestSignal(t, d.closed)
}

func TestDiagnosticsExternalClosePreservesAcceptedWriteCompletion(t *testing.T) {
	d := &readFailureDuringWriteDevice{entered: make(chan struct{}), releaseRead: make(chan struct{}), releaseWrite: make(chan struct{}), closed: make(chan struct{})}
	var rr, wr sync.Once
	t.Cleanup(func() { rr.Do(func() { close(d.releaseRead) }); wr.Do(func() { close(d.releaseWrite) }) })
	n := &Native{open: func(driver.Endpoint) (driver.Device, error) { return d, nil }}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := n.Open(ctx, Endpoint{ID: "diagnostic-write-result"})
	if err != nil {
		t.Fatal(err)
	}
	type answer struct {
		r WriteResult
		e error
	}
	done := make(chan answer, 1)
	go func() { r, e := c.Write(ctx, Report{Data: []byte{1}}); done <- answer{r, e} }()
	waitLifecycleTestSignal(t, d.entered)
	expired, stop := context.WithCancel(context.Background())
	stop()
	if err := c.Close(expired); !errors.Is(err, context.Canceled) {
		t.Fatalf("close=%v", err)
	}
	rr.Do(func() { close(d.releaseRead) })
	wr.Do(func() { close(d.releaseWrite) })
	select {
	case a := <-done:
		var native *NativeError
		if a.r.Outcome != OutcomeCompleted || !errors.As(a.e, &native) || native.Domain != "pthread" || native.Code != 5 {
			t.Fatalf("completed write=%+v err=%v", a.r, a.e)
		}
	case <-ctx.Done():
		t.Fatal("write completion timed out")
	}
	if err := c.Close(ctx); err != nil {
		t.Fatal(err)
	}
}
