package usb

import (
	"context"
	"errors"
	"time"

	"github.com/PeculiarVentures/fido-go/pkg/transport"
)

const hidReadPollInterval = 100 * time.Millisecond

// requestClose stops admission immediately and schedules physical cleanup. It
// never waits for native I/O, so cancellation can return while a write is active.
func (session *hidSession) requestClose() <-chan struct{} {
	session.closeOnce.Do(func() {
		session.closing.Store(true)
		session.closeDone = make(chan struct{})
		go func() {
			// The same lock protects the entire native call, including go-hid's
			// error retrieval. hid_close must never overlap any use of its handle.
			session.devMu.Lock()
			if session.dev != nil {
				session.closeErr = session.dev.Close()
				session.dev = nil
			}
			session.devMu.Unlock()
			close(session.closeDone)
		}()
	})
	return session.closeDone
}

func (session *hidSession) hidCallError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if session.closing.Load() {
		return transport.Disconnected(errors.New("transport/usb: hid device is closed"))
	}
	return nil
}

func (session *hidSession) runHIDCall(ctx context.Context, call func(hidDevice) (int, error)) (int, error) {
	if err := session.hidCallError(ctx); err != nil {
		return 0, err
	}
	return runCancelableHIDCall(ctx, func() (int, error) {
		session.devMu.Lock()
		defer session.devMu.Unlock()
		// Recheck after admission: Close/cancellation may have won while this
		// goroutine was queued or before it was scheduled by the runtime.
		if err := session.hidCallError(ctx); err != nil {
			return 0, err
		}
		if session.dev == nil {
			return 0, transport.Disconnected(errors.New("transport/usb: hid device is closed"))
		}
		return call(session.dev)
	}, func() error {
		session.requestClose()
		return nil
	})
}

type hidCallResult[T any] struct {
	value T
	err   error
}

// runCancelableHIDCall requires a nonblocking cancellation callback. Physical
// handle cleanup must remain serialized with the native call.
func runCancelableHIDCall[T any](ctx context.Context, call func() (T, error), cancelFn func() error) (T, error) {
	var zero T
	resultCh := make(chan hidCallResult[T], 1)
	go func() {
		value, err := call()
		resultCh <- hidCallResult[T]{value: value, err: err}
	}()

	select {
	case result := <-resultCh:
		// A polling worker can notice cancellation before this select does.
		// Retire the session even when the worker result wins the select.
		if err := ctx.Err(); err != nil {
			_ = cancelFn()
			return zero, err
		}
		return result.value, result.err
	case <-ctx.Done():
		_ = cancelFn()
		return zero, ctx.Err()
	}
}
