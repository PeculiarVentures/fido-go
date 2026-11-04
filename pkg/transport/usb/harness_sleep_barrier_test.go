//go:build hid_diagnostics

package usb_test

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/PeculiarVentures/fido-go/pkg/hid"
)

// usbSleepHIDBackend decorates the public HID boundary only. Production USB
// discovery, channel initialization and message exchange remain unchanged.
type usbSleepHIDBackend struct {
	raw         hid.Backend
	mu          sync.Mutex
	connections map[hid.EndpointID]*usbSleepHIDConn
	inventory   hid.Snapshot
}

func newUSBSleepHIDBackend(raw hid.Backend) *usbSleepHIDBackend {
	return &usbSleepHIDBackend{raw: raw, connections: make(map[hid.EndpointID]*usbSleepHIDConn)}
}
func (backend *usbSleepHIDBackend) Enumerate(ctx context.Context, options hid.EnumerateOptions) (hid.Snapshot, error) {
	snapshot, err := backend.raw.Enumerate(ctx, options)
	backend.mu.Lock()
	backend.inventory = hid.Snapshot{Complete: snapshot.Complete, Endpoints: append([]hid.Endpoint(nil), snapshot.Endpoints...)}
	backend.mu.Unlock()
	return snapshot, err
}
func (backend *usbSleepHIDBackend) Open(ctx context.Context, endpoint hid.Endpoint) (hid.Conn, error) {
	raw, err := backend.raw.Open(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, hid.ErrIO
	}
	conn := &usbSleepHIDConn{raw: raw, stop: make(chan struct{})}
	backend.mu.Lock()
	backend.connections[raw.Endpoint().ID] = conn
	backend.mu.Unlock()
	return conn, nil
}
func (backend *usbSleepHIDBackend) connection(id hid.EndpointID) (*usbSleepHIDConn, error) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	conn := backend.connections[id]
	if conn == nil {
		return nil, errors.New("USB diagnostic has no matching opened HID connection")
	}
	return conn, nil
}
func (backend *usbSleepHIDBackend) snapshot() hid.Snapshot {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	return hid.Snapshot{Complete: backend.inventory.Complete, Endpoints: append([]hid.Endpoint(nil), backend.inventory.Endpoints...)}
}

type usbSleepBarrierSnapshot struct {
	Armed, ReadEntered, Released, Closed, ReadActive bool
	ConfirmedWrites, ExpectedWrites, ForwardedReads  uint64
}

type usbSleepHIDConn struct {
	raw                                                       hid.Conn
	mu                                                        sync.Mutex
	armed, entered, released, closed, readActive, writeActive bool
	writes, expected, forwardedReads                          uint64
	gate, readEntry, stop                                     chan struct{}
	responseCtx                                               context.Context
}

func (conn *usbSleepHIDConn) Endpoint() hid.Endpoint   { return conn.raw.Endpoint() }
func (conn *usbSleepHIDConn) Layout() hid.ReportLayout { return conn.raw.Layout() }

func (conn *usbSleepHIDConn) arm(expectedWrites uint64) error {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if conn.closed {
		return hid.ErrClosed
	}
	if conn.armed || conn.readActive || conn.writeActive {
		return hid.ErrBusy
	}
	if expectedWrites == 0 {
		return hid.ErrInvalidArgument
	}
	conn.armed = true
	conn.expected = expectedWrites
	conn.writes = 0
	conn.forwardedReads = 0
	conn.gate = make(chan struct{})
	conn.readEntry = make(chan struct{})
	return nil
}
func (conn *usbSleepHIDConn) snapshot() usbSleepBarrierSnapshot {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return usbSleepBarrierSnapshot{Armed: conn.armed, ReadEntered: conn.entered, Released: conn.released, Closed: conn.closed, ReadActive: conn.readActive, ConfirmedWrites: conn.writes, ExpectedWrites: conn.expected, ForwardedReads: conn.forwardedReads}
}
func (conn *usbSleepHIDConn) waitRead(ctx context.Context) error {
	conn.mu.Lock()
	entry, stop, armed := conn.readEntry, conn.stop, conn.armed
	conn.mu.Unlock()
	if !armed {
		return hid.ErrInvalidArgument
	}
	select {
	case <-entry:
		return nil
	case <-stop:
		return hid.ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (conn *usbSleepHIDConn) release(responseCtx context.Context) error {
	if responseCtx == nil {
		return hid.ErrInvalidArgument
	}
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if !conn.armed {
		return hid.ErrInvalidArgument
	}
	if conn.closed {
		return hid.ErrClosed
	}
	if !conn.released {
		conn.responseCtx = responseCtx
		conn.released = true
		close(conn.gate)
	}
	return nil
}

func (conn *usbSleepHIDConn) Read(ctx context.Context, wait time.Duration) (hid.Report, error) {
	if ctx == nil || wait < 0 {
		return hid.Report{}, hid.ErrInvalidArgument
	}
	if err := ctx.Err(); err != nil {
		return hid.Report{}, err
	}
	conn.mu.Lock()
	if conn.closed {
		conn.mu.Unlock()
		return hid.Report{}, hid.ErrClosed
	}
	if conn.readActive {
		conn.mu.Unlock()
		return hid.Report{}, hid.ErrBusy
	}
	conn.readActive = true
	armed, gate, stop := conn.armed, conn.gate, conn.stop
	if armed && !conn.entered {
		conn.entered = true
		close(conn.readEntry)
	}
	conn.mu.Unlock()
	defer func() { conn.mu.Lock(); conn.readActive = false; conn.mu.Unlock() }()
	if armed {
		select {
		case <-gate:
		case <-ctx.Done():
			return hid.Report{}, ctx.Err()
		case <-stop:
			return hid.Report{}, hid.ErrClosed
		}
	}
	conn.mu.Lock()
	if err := ctx.Err(); err != nil {
		conn.mu.Unlock()
		return hid.Report{}, err
	}
	if conn.closed {
		conn.mu.Unlock()
		return hid.Report{}, hid.ErrClosed
	}
	phaseCtx := conn.responseCtx
	if armed {
		conn.forwardedReads++
	}
	conn.mu.Unlock()
	readCtx := ctx
	if armed && phaseCtx != nil {
		var cleanup func()
		readCtx, cleanup = usbSleepReadContext(ctx, phaseCtx)
		defer cleanup()
	}
	return conn.raw.Read(readCtx, wait)
}
func (conn *usbSleepHIDConn) Write(ctx context.Context, report hid.Report) (hid.WriteResult, error) {
	rejected := hid.WriteResult{Outcome: hid.OutcomeNotSubmitted}
	if ctx == nil {
		return rejected, hid.ErrInvalidArgument
	}
	if err := ctx.Err(); err != nil {
		return rejected, err
	}
	conn.mu.Lock()
	if conn.closed {
		conn.mu.Unlock()
		return rejected, hid.ErrClosed
	}
	if conn.writeActive {
		conn.mu.Unlock()
		return rejected, hid.ErrBusy
	}
	conn.writeActive = true
	conn.mu.Unlock()
	defer func() { conn.mu.Lock(); conn.writeActive = false; conn.mu.Unlock() }()
	result, err := conn.raw.Write(ctx, report)
	conn.mu.Lock()
	if conn.armed && result.Outcome == hid.OutcomeCompleted {
		conn.writes++
	}
	conn.mu.Unlock()
	return result, err
}
func (conn *usbSleepHIDConn) Close(ctx context.Context) error {
	conn.mu.Lock()
	if !conn.closed {
		conn.closed = true
		close(conn.stop)
	}
	conn.mu.Unlock()
	// Production retire intentionally uses a canceled context here. This wrapper
	// records no cleanup verdict: explicit Session.CloseContext owns that evidence.
	return conn.raw.Close(ctx)
}

var _ hid.Backend = (*usbSleepHIDBackend)(nil)
var _ hid.Conn = (*usbSleepHIDConn)(nil)

// Honor both the production caller and the post-wake response budget. The
// short AfterFunc callback is joined before this Read returns; no native reader
// or cancellation helper is abandoned in a detached goroutine.
func usbSleepReadContext(caller, phase context.Context) (context.Context, func()) {
	var bounded context.Context
	var cancel context.CancelFunc
	if deadline, ok := phase.Deadline(); ok {
		bounded, cancel = context.WithDeadline(caller, deadline)
	} else {
		bounded, cancel = context.WithCancel(caller)
	}
	done := make(chan struct{})
	stop := context.AfterFunc(phase, func() {
		if !errors.Is(phase.Err(), context.DeadlineExceeded) {
			cancel()
		}
		close(done)
	})
	return bounded, func() {
		if !stop() {
			<-done
		}
		cancel()
	}
}
