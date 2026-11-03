//go:build hid_diagnostics

package usb_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/PeculiarVentures/fido-go/pkg/hid"
	"github.com/PeculiarVentures/fido-go/pkg/transport/usb"
)

func newProductionSleepFixture(t *testing.T) (usb.HIDSession, *usbSleepHIDConn) {
	t.Helper()
	id := hid.EndpointID("private-sleep-fixture")
	raw := &diagnosticEchoBackend{endpoints: []hid.Endpoint{{ID: id, Bus: hid.BusUSB, Usage: hid.Field[hid.Usage]{Known: true, Value: hid.Usage{Page: 0xf1d0, ID: 1}}}}}
	decorator := newUSBSleepHIDBackend(raw)
	backend, err := usb.NewHIDBackendWithHID(decorator)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	devices, err := backend.Discover(ctx)
	if err != nil || len(devices) != 1 {
		t.Fatalf("discover: %v", err)
	}
	session, err := backend.Open(ctx, devices[0])
	if err != nil {
		t.Fatal(err)
	}
	h, ok := session.(usb.HIDSession)
	if !ok {
		t.Fatal("missing production HIDSession")
	}
	t.Cleanup(func() { _ = session.Close() })
	warm := []byte("warm")
	echo, err := h.ExchangeHID(ctx, 1, warm)
	if err != nil || !bytes.Equal(echo, warm) {
		t.Fatalf("warmup: %v", err)
	}
	gate, err := decorator.connection(id)
	if err != nil {
		t.Fatal(err)
	}
	return h, gate
}
func TestUSBSleepGateHoldsProductionExchangeAfterAllWrites(t *testing.T) {
	session, gate := newProductionSleepFixture(t)
	if err := gate.arm(18); err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0x5a}, 1024)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	type answer struct {
		data []byte
		err  error
	}
	done := make(chan answer, 1)
	go func() { data, err := session.ExchangeHID(ctx, 1, payload); done <- answer{data, err} }()
	if err := gate.waitRead(ctx); err != nil {
		t.Fatal(err)
	}
	before := gate.snapshot()
	if !before.Armed || !before.ReadEntered || before.ConfirmedWrites != 18 || before.ExpectedWrites != 18 || before.ForwardedReads != 0 || before.Released {
		t.Fatalf("pre-release barrier=%+v", before)
	}
	select {
	case <-done:
		t.Fatal("exchange completed before response gate release")
	default:
	}
	if err := gate.release(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case a := <-done:
		if a.err != nil || !bytes.Equal(a.data, payload) {
			t.Fatalf("echo=%v", a.err)
		}
	case <-ctx.Done():
		t.Fatal("exchange did not finish")
	}
	after := gate.snapshot()
	if !after.Released || after.ForwardedReads != 18 {
		t.Fatalf("post-release barrier=%+v", after)
	}
}
func TestUSBSleepGateCancellationReleasesProductionWaiter(t *testing.T) {
	session, gate := newProductionSleepFixture(t)
	if err := gate.arm(18); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := session.ExchangeHID(ctx, 1, bytes.Repeat([]byte{1}, 1024)); done <- err }()
	bounded, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	if err := gate.waitRead(bounded); err != nil {
		cancel()
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled exchange=%v", err)
		}
	case <-bounded.Done():
		t.Fatal("canceled exchange did not return")
	}
	if gate.snapshot().ForwardedReads != 0 {
		t.Fatal("canceled gate forwarded a native read")
	}
}

type blockingSleepReadConn struct {
	hid.Conn
	entered, returned chan struct{}
}

func (c *blockingSleepReadConn) Read(ctx context.Context, _ time.Duration) (hid.Report, error) {
	close(c.entered)
	<-ctx.Done()
	close(c.returned)
	return hid.Report{}, ctx.Err()
}
func TestUSBSleepGatePreservesCallerCancellationAfterRelease(t *testing.T) {
	session, gate := newProductionSleepFixture(t)
	raw := &blockingSleepReadConn{Conn: gate.raw, entered: make(chan struct{}), returned: make(chan struct{})}
	gate.raw = raw
	if err := gate.arm(18); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := session.ExchangeHID(ctx, 1, bytes.Repeat([]byte{7}, 1024)); done <- err }()
	bounded, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	if err := gate.waitRead(bounded); err != nil {
		t.Fatal(err)
	}
	if err := gate.release(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-raw.entered:
	case <-bounded.Done():
		t.Fatal("forwarded read did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled active read=%v", err)
		}
	case <-bounded.Done():
		t.Fatal("cancellation after release did not return")
	}
	select {
	case <-raw.returned:
	case <-bounded.Done():
		t.Fatal("native read waiter remained after cancellation")
	}
}

type errorSleepReadConn struct {
	hid.Conn
	err error
}

func (c *errorSleepReadConn) Read(context.Context, time.Duration) (hid.Report, error) {
	return hid.Report{}, c.err
}
func TestUSBSleepProductionExchangeErrorPreservesDeliveryEvidence(t *testing.T) {
	session, gate := newProductionSleepFixture(t)
	source := &hid.Error{Op: "read", Endpoint: "private-sleep-fixture", Kind: hid.ErrIO, Native: &hid.NativeError{Domain: "iokit", Code: 0xe00002bc}}
	gate.raw = &errorSleepReadConn{Conn: gate.raw, err: source}
	if err := gate.arm(18); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := session.ExchangeHID(ctx, 1, bytes.Repeat([]byte{4}, 1024)); done <- err }()
	if err := gate.waitRead(ctx); err != nil {
		t.Fatal(err)
	}
	if err := gate.release(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		var ex *usb.ExchangeError
		var native *hid.NativeError
		if !errors.As(err, &ex) || ex.Stage != usb.StageResponse || ex.PacketsSubmitted != 18 || ex.Outcome != hid.OutcomeCompleted || !ex.Ambiguous || !errors.As(err, &native) || native.Domain != "iokit" || native.Code != 0xe00002bc {
			t.Fatalf("delivery error=%v", err)
		}
	case <-ctx.Done():
		t.Fatal("exchange did not return")
	}
}

func TestUSBSleepGateCloseReleasesHeldProductionExchange(t *testing.T) {
	session, gate := newProductionSleepFixture(t)
	if err := gate.arm(18); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := session.ExchangeHID(ctx, 1, bytes.Repeat([]byte{8}, 1024)); done <- err }()
	if err := gate.waitRead(ctx); err != nil {
		t.Fatal(err)
	}
	closer, ok := session.(interface{ CloseContext(context.Context) error })
	if !ok {
		t.Fatal("production session lacks context closer")
	}
	if err := closer.CloseContext(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, hid.ErrClosed) {
			t.Fatalf("closed exchange=%v", err)
		}
	case <-ctx.Done():
		t.Fatal("close did not release exchange")
	}
	if !gate.snapshot().Closed || gate.snapshot().ForwardedReads != 0 {
		t.Fatalf("closed gate=%+v", gate.snapshot())
	}
}

func TestUSBSleepGatePostWakeDeadlineStopsProductionRead(t *testing.T) {
	session, gate := newProductionSleepFixture(t)
	raw := &blockingSleepReadConn{Conn: gate.raw, entered: make(chan struct{}), returned: make(chan struct{})}
	gate.raw = raw
	if err := gate.arm(18); err != nil {
		t.Fatal(err)
	}
	outer, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := session.ExchangeHID(outer, 1, bytes.Repeat([]byte{9}, 1024)); done <- err }()
	if err := gate.waitRead(outer); err != nil {
		t.Fatal(err)
	}
	phase, stop := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer stop()
	if err := gate.release(phase); err != nil {
		t.Fatal(err)
	}
	select {
	case <-raw.entered:
	case <-outer.Done():
		t.Fatal("raw read did not start")
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("post-wake timeout=%v", err)
		}
	case <-outer.Done():
		t.Fatal("post-wake timeout did not return")
	}
	select {
	case <-raw.returned:
	case <-outer.Done():
		t.Fatal("raw read waiter did not finish")
	}
}
