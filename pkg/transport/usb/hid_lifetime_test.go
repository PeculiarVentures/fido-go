package usb

import (
	"context"
	"errors"
	"github.com/PeculiarVentures/fido-go/pkg/hid"
	"testing"
	"time"
)

func TestHIDSessionCloseRetiresAndPreservesCleanupError(t *testing.T) {
	session, dev := newTestHIDSession(t)
	failure := errors.New("cleanup failure")
	dev.closeErr = failure
	if err := session.Close(); !errors.Is(err, failure) {
		t.Fatalf("close: %v", err)
	}
	if err := session.Close(); !errors.Is(err, failure) {
		t.Fatalf("repeated close: %v", err)
	}
	if _, err := session.ExchangeHID(context.Background(), 0x42, nil); !errors.Is(err, hid.ErrClosed) {
		t.Fatalf("exchange after close: %v", err)
	}
}
func TestHIDSessionCloseContextCanceledStillRetires(t *testing.T) {
	session, dev := newTestHIDSession(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = session.CloseContext(ctx)
	select {
	case <-dev.closed:
	case <-time.After(time.Second):
		t.Fatal("close did not retire connection")
	}
	if _, err := session.ExchangeHID(context.Background(), 0x42, nil); !errors.Is(err, hid.ErrClosed) {
		t.Fatalf("exchange after close: %v", err)
	}
}
