package usb

import (
	"bytes"
	"context"
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/PeculiarVentures/fido-go/pkg/transport"
)

// observedHIDContext signals after runCancelableHIDCall has launched its worker.
// Holding devMu then makes the close-before-native-admission race deterministic.
type observedHIDContext struct {
	context.Context
	once     sync.Once
	observed chan struct{}
}

func (ctx *observedHIDContext) Done() <-chan struct{} {
	ctx.once.Do(func() { close(ctx.observed) })
	return ctx.Context.Done()
}

func awaitHIDSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(time.Second):
		t.Fatal("native I/O synchronization timed out")
	}
}

func TestHIDSessionCloseBeforeNativeAdmission(t *testing.T) {
	t.Parallel()
	for _, write := range []bool{false, true} {
		t.Run(map[bool]string{false: "read", true: "write"}[write], func(t *testing.T) {
			session, dev := newTestHIDSession(t)
			ctx := &observedHIDContext{Context: context.Background(), observed: make(chan struct{})}
			result := make(chan error, 1)
			func() {
				session.devMu.Lock()
				defer session.devMu.Unlock()
				go func() {
					var err error
					if write {
						err = session.writePacket(ctx, make([]byte, hidReportSize))
					} else {
						_, err = session.readPacket(ctx)
					}
					result <- err
				}()
				awaitHIDSignal(t, ctx.observed)
				session.requestClose()
			}()
			if err := awaitHIDResult(t, result); !errors.Is(err, transport.ErrDisconnected) {
				t.Fatalf("queued native call = %v", err)
			}
			if err := session.Close(); err != nil {
				t.Fatal(err)
			}
			if len(dev.writtenPackets()) != 0 || len(dev.readStarted) != 0 {
				t.Fatal("native I/O started after shutdown was requested")
			}
		})
	}
}

func TestHIDSessionCancelBeforeNativeAdmissionReturnsWithoutWaiting(t *testing.T) {
	t.Parallel()
	session, dev := newTestHIDSession(t)
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &observedHIDContext{Context: parent, observed: make(chan struct{})}
	result := make(chan error, 1)
	func() {
		session.devMu.Lock()
		defer session.devMu.Unlock()
		go func() { result <- session.writePacket(ctx, make([]byte, hidReportSize)) }()
		awaitHIDSignal(t, ctx.observed)
		cancel()
		if err := awaitHIDResult(t, result); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled native admission = %v", err)
		}
		select {
		case <-dev.closed:
			t.Fatal("handle freed without acquiring the native I/O lock")
		default:
		}
	}()
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if len(dev.writtenPackets()) != 0 {
		t.Fatal("canceled worker started a native write")
	}
}

func TestHIDSessionCloseWaitsForNativeWriteAndRejectsNewIO(t *testing.T) {
	t.Parallel()
	session, dev := newTestHIDSession(t)
	started, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	releaseWrite := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseWrite)
	dev.onWrite = func([]byte) error { close(started); <-release; return nil }
	writeResult := make(chan error, 1)
	go func() { writeResult <- session.writePacket(context.Background(), make([]byte, hidReportSize)) }()
	awaitHIDSignal(t, started)
	done := session.requestClose()
	closeResult := make(chan error, 1)
	go func() { closeResult <- session.Close() }()
	select {
	case <-done:
		t.Fatal("physical close finished while native Write still owns the handle")
	default:
	}
	if _, err := session.readPacket(context.Background()); !errors.Is(err, transport.ErrDisconnected) {
		t.Fatalf("new I/O during shutdown = %v", err)
	}
	dev.mu.Lock()
	active, closes := dev.active, dev.closeCalls
	dev.mu.Unlock()
	if active != 1 || closes != 0 {
		t.Fatalf("handle ownership while writing: active=%d closes=%d", active, closes)
	}
	releaseWrite()
	if err := awaitHIDResult(t, writeResult); err != nil {
		t.Fatal(err)
	}
	if err := awaitHIDResult(t, closeResult); err != nil {
		t.Fatal(err)
	}
}

func TestHIDSessionConcurrentClosePreservesSingleCleanupError(t *testing.T) {
	t.Parallel()
	session, dev := newTestHIDSession(t)
	failure := errors.New("native close failure")
	dev.closeErr = failure
	const callers = 32
	start, results := make(chan struct{}), make(chan error, callers)
	for range callers {
		go func() { <-start; results <- session.Close() }()
	}
	close(start)
	for range callers {
		if err := awaitHIDResult(t, results); !errors.Is(err, failure) {
			t.Fatalf("close error = %v, want original cleanup failure", err)
		}
	}
	if err := session.Close(); !errors.Is(err, failure) {
		t.Fatalf("repeated close error = %v", err)
	}
}

func TestHIDSessionReadPollTimeoutKeepsWaitingForPacket(t *testing.T) {
	t.Parallel()
	session, dev := newTestHIDSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	result := make(chan error, 1)
	want := bytes.Repeat([]byte{0xab}, hidReportSize)
	go func() {
		packet, err := session.readPacket(ctx)
		if err == nil && !bytes.Equal(packet, want) {
			err = errors.New("read poll changed the packet")
		}
		result <- err
	}()
	awaitHIDRead(t, dev)
	awaitHIDRead(t, dev) // At least one bounded wait expired without a packet.
	select {
	case err := <-result:
		t.Fatalf("poll timeout escaped as an exchange result: %v", err)
	default:
	}
	dev.reads <- want
	if err := awaitHIDResult(t, result); err != nil {
		t.Fatal(err)
	}
}

func TestHIDSessionConcurrentExchangeAndCloseNeverFreeActiveHandle(t *testing.T) {
	previous := runtime.GOMAXPROCS(2)
	defer runtime.GOMAXPROCS(previous)
	packet := framedHIDPayload(t, testChannelID, 0xc2, []byte{0})[0]
	for iteration := range 2000 {
		dev := newFakeHIDDevice()
		session := &hidSession{dev: dev, channelID: testChannelID, reportSize: hidReportSize}
		dev.reads <- packet
		start := make(chan struct{})
		result := make(chan error, 1)
		go func() { <-start; _, err := session.ExchangeHID(context.Background(), 0x42, []byte{0}); result <- err }()
		close(start)
		if iteration%2 == 0 {
			runtime.Gosched()
		}
		if err := session.Close(); err != nil {
			t.Fatal(err)
		}
		if err := awaitHIDResult(t, result); err != nil && !errors.Is(err, transport.ErrDisconnected) {
			t.Fatal(err)
		}
		dev.mu.Lock()
		active, violations, closes := dev.active, dev.violations, dev.closeCalls
		dev.mu.Unlock()
		if active != 0 || violations != 0 || closes != 1 {
			t.Fatalf("native lifetime: active=%d unsafe accesses=%d closes=%d", active, violations, closes)
		}
	}
}

func TestRunCancelableHIDCallRetiresSessionWhenWorkerNoticesCancellation(t *testing.T) {
	t.Parallel()
	for range 100 {
		ctx, cancel := context.WithCancel(context.Background())
		stops := 0
		_, err := runCancelableHIDCall(ctx, func() (int, error) {
			cancel()
			return 0, ctx.Err()
		}, func() error {
			stops++
			return nil
		})
		if !errors.Is(err, context.Canceled) || stops != 1 {
			t.Fatalf("worker cancellation = %v, shutdown requests = %d", err, stops)
		}
	}
}
