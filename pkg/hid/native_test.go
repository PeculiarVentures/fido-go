package hid

import (
	"context"
	"errors"
	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/driver"
	"testing"
	"time"
)

type fakeDevice struct {
	endpoint     driver.Endpoint
	reads        chan driver.Report
	writes       chan driver.Report
	releaseWrite chan struct{}
	closed       chan struct{}
}

func (f *fakeDevice) Endpoint() driver.Endpoint { return f.endpoint }
func (f *fakeDevice) Layout() driver.Layout {
	return driver.Layout{Input: driver.ReportSpec{ID: 1, Size: 2}, Output: driver.ReportSpec{ID: 2, Size: 2}}
}
func (f *fakeDevice) Read(wait time.Duration) (driver.Report, error) {
	select {
	case r := <-f.reads:
		return r, nil
	case <-time.After(wait):
		return driver.Report{}, &driver.Error{Kind: driver.KindTimeout}
	}
}
func (f *fakeDevice) Write(r driver.Report) (driver.WriteResult, error) {
	f.writes <- r
	if f.releaseWrite != nil {
		<-f.releaseWrite
	}
	return driver.WriteResult{Outcome: driver.OutcomeCompleted}, nil
}
func (f *fakeDevice) Close() error { close(f.closed); return nil }
func newFake(id string) *fakeDevice {
	return &fakeDevice{endpoint: driver.Endpoint{ID: id}, reads: make(chan driver.Report, 128), writes: make(chan driver.Report, 1), closed: make(chan struct{})}
}
func openFake(t *testing.T, f *fakeDevice) Conn {
	t.Helper()
	n := &Native{open: func(driver.Endpoint) (driver.Device, error) { return f, nil }}
	c, err := n.Open(context.Background(), Endpoint{ID: EndpointID(f.endpoint.ID)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := c.Close(ctx); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	return c
}
func TestEnumerateFilterAndPartial(t *testing.T) {
	n := &Native{enumerate: func(bool) (driver.Snapshot, error) {
		return driver.Snapshot{Complete: true, Endpoints: []driver.Endpoint{{ID: "zero", VendorID: driver.Field[uint16]{Known: true}, Serial: driver.Field[string]{Known: true}}, {ID: "unknown"}, {ID: "other", VendorID: driver.Field[uint16]{Known: true, Value: 2}}}}, nil
	}}
	zero := uint16(0)
	s, err := n.Enumerate(context.Background(), EnumerateOptions{Filter: Filter{VendorID: &zero}, ResolveStrings: true})
	if err != nil || s.Complete || len(s.Warnings) == 0 || len(s.Endpoints) != 1 || s.Endpoints[0].ID != "zero" || !s.Endpoints[0].Serial.Known {
		t.Fatalf("snapshot=%+v err=%v", s, err)
	}
	s, err = n.Enumerate(context.Background(), EnumerateOptions{})
	if err != nil || !s.Complete || len(s.Endpoints) != 3 || s.Endpoints[0].Serial.Known {
		t.Fatalf("snapshot=%+v err=%v", s, err)
	}
}
func TestOpenRejectsStaleMetadata(t *testing.T) {
	f := newFake("stale")
	f.endpoint.VendorID = driver.Field[uint16]{Known: true, Value: 2}
	n := &Native{open: func(driver.Endpoint) (driver.Device, error) { return f, nil }}
	_, err := n.Open(context.Background(), Endpoint{ID: "stale", VendorID: Field[uint16]{Known: true, Value: 1}})
	if !errors.Is(err, ErrStaleEndpoint) {
		t.Fatal(err)
	}
	select {
	case <-f.closed:
	default:
		t.Fatal("stale device not closed")
	}
}
func TestReadTimeoutDoesNotConsumeNextReport(t *testing.T) {
	f := newFake("timeout")
	c := openFake(t, f)
	if _, err := c.Read(context.Background(), time.Millisecond); !errors.Is(err, ErrTimeout) {
		t.Fatal(err)
	}
	f.reads <- driver.Report{ID: 1, Data: []byte{3, 4}}
	r, err := c.Read(context.Background(), time.Second)
	if err != nil || len(r.Data) != 2 || r.Data[0] != 3 {
		t.Fatalf("%+v %v", r, err)
	}
}
func TestCanceledWriteRetainsCopyAndLeaseUntilCompletion(t *testing.T) {
	f := newFake("pending")
	f.releaseWrite = make(chan struct{})
	c := openFake(t, f)
	ctx, cancel := context.WithCancel(context.Background())
	data := []byte{3, 4}
	done := make(chan WriteResult, 1)
	go func() { r, _ := c.Write(ctx, Report{ID: 2, Data: data}); done <- r }()
	written := <-f.writes
	cancel()
	result := <-done
	if result.Outcome != OutcomeUnknown {
		t.Fatalf("outcome=%v", result.Outcome)
	}
	data[0] = 9
	if written.Data[0] != 3 {
		t.Fatal("write buffer not copied")
	}
	n := &Native{open: func(driver.Endpoint) (driver.Device, error) { t.Error("busy endpoint reopened"); return nil, nil }}
	if _, err := n.Open(context.Background(), Endpoint{ID: "pending"}); !errors.Is(err, ErrBusy) {
		t.Fatalf("expected busy: %v", err)
	}
	select {
	case <-f.closed:
		t.Fatal("closed during write")
	default:
	}
	close(f.releaseWrite)
}
func TestInvalidWriteAndNativeError(t *testing.T) {
	f := newFake("invalid")
	c := openFake(t, f)
	r, err := c.Write(context.Background(), Report{ID: 2, Data: []byte{1}})
	if r.Outcome != OutcomeNotSubmitted || !errors.Is(err, ErrInvalidReport) {
		t.Fatalf("%+v %v", r, err)
	}
	e := operationError("write", "x", &driver.Error{Kind: driver.KindIO, Domain: "iokit", Code: 12, Cause: context.Canceled})
	var native *NativeError
	if !errors.Is(e, ErrIO) || !errors.Is(e, context.Canceled) || !errors.As(e, &native) || native.Code != 12 {
		t.Fatalf("error chain: %v", e)
	}
}

func TestCanceledOpenRetainsLeaseUntilLateClose(t *testing.T) {
	f := newFake("late-open")
	started, release := make(chan struct{}), make(chan struct{})
	n := &Native{open: func(driver.Endpoint) (driver.Device, error) { close(started); <-release; return f, nil }}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := n.Open(ctx, Endpoint{ID: "late-open"}); done <- err }()
	<-started
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := n.Open(context.Background(), Endpoint{ID: "late-open"}); !errors.Is(err, ErrBusy) {
		t.Fatalf("pending open lease: %v", err)
	}
	close(release)
	select {
	case <-f.closed:
	case <-time.After(time.Second):
		t.Fatal("late device not closed")
	}
}
func TestConcurrentReadBusyAndCancellationRetires(t *testing.T) {
	f := newFake("read-busy")
	c := openFake(t, f)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := c.Read(ctx, 0); done <- err }()
	// Observe the admitted read under its lock, rather than relying on timing.
	concrete := c.(*connection)
	deadline := time.Now().Add(time.Second)
	for {
		concrete.mu.Lock()
		busy := concrete.readBusy
		concrete.mu.Unlock()
		if busy {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("read not admitted")
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := c.Read(context.Background(), 0); !errors.Is(err, ErrBusy) {
		t.Fatalf("second read: %v", err)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := c.Read(context.Background(), 0); !errors.Is(err, ErrClosed) {
		t.Fatalf("read after cancellation: %v", err)
	}
}
func TestInputOverflowRetiresConnection(t *testing.T) {
	f := newFake("overflow")
	c := openFake(t, f)
	for i := 0; i <= driver.InputQueueSize; i++ {
		f.reads <- driver.Report{ID: 1, Data: []byte{1, 2}}
	}
	deadline := time.Now().Add(time.Second)
	for {
		concrete := c.(*connection)
		concrete.mu.Lock()
		retiring := concrete.retiring
		concrete.mu.Unlock()
		if retiring {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("overflow did not retire")
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := c.Read(context.Background(), 0); !errors.Is(err, ErrClosed) || !errors.Is(err, ErrIO) {
		t.Fatalf("overflow: %v", err)
	}
}

func TestFilterConjunctionCanExcludeKnownMismatchWithoutIncompleteSnapshot(t *testing.T) {
	n := &Native{enumerate: func(bool) (driver.Snapshot, error) {
		return driver.Snapshot{Complete: true, Endpoints: []driver.Endpoint{{ID: "not-vendor", VendorID: driver.Field[uint16]{Known: true, Value: 5}}, {ID: "yes", VendorID: driver.Field[uint16]{Known: true, Value: 0}, ProductID: driver.Field[uint16]{Known: true, Value: 2}}}}, nil
	}}
	zero, two := uint16(0), uint16(2)
	s, err := n.Enumerate(context.Background(), EnumerateOptions{Filter: Filter{VendorID: &zero, ProductID: &two}})
	if err != nil || !s.Complete || len(s.Endpoints) != 1 || s.Endpoints[0].ID != "yes" {
		t.Fatalf("snapshot=%+v error=%v", s, err)
	}
}
func TestOpenRejectsUnboundedMetadataBeforeCallingDriver(t *testing.T) {
	called := false
	n := &Native{open: func(driver.Endpoint) (driver.Device, error) { called = true; return nil, nil }}
	e := Endpoint{ID: "bounded", Serial: Field[string]{Value: string(make([]byte, driver.MaxMetadataSize+1))}}
	if _, err := n.Open(context.Background(), e); !errors.Is(err, ErrInvalidArgument) || called {
		t.Fatalf("error=%v called=%v", err, called)
	}
}
