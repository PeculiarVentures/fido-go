//go:build hid_diagnostics && integration && darwin && cgo

package power_test

import (
	"context"
	"errors"
	"github.com/PeculiarVentures/fido-go/internal/diagnostics/power"
	"os"
	"testing"
)

func TestSharedPowerObserverRegistration(t *testing.T) {
	if os.Getenv("FIDO_USB_POWER_OBSERVER_TEST") != "1" {
		t.Skip("set FIDO_USB_POWER_OBSERVER_TEST=1 for read-only observer registration")
	}
	if !power.Available() {
		t.Fatal("native observer unavailable")
	}
	observer, err := power.New()
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Close()
	s := observer.Snapshot()
	if !s.Ready || s.Synthetic || s.ObserverGeneration == 0 {
		t.Fatalf("registration=%+v", s)
	}
	gen, err := observer.Arm()
	if err != nil || gen == 0 {
		t.Fatalf("arm=%d %v", gen, err)
	}
	s = observer.Snapshot()
	if !s.Ready || !s.Armed || s.Synthetic || s.ArmGeneration != gen {
		t.Fatalf("armed=%+v", s)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = observer.Wait(ctx, gen); !errors.Is(err, context.Canceled) {
		t.Fatalf("wait=%v", err)
	}
	if err = observer.Close(); err != nil {
		t.Fatal(err)
	}
	s = observer.Snapshot()
	if !s.Closed || !s.ThreadJoined || !s.Released || s.Synthetic {
		t.Fatalf("cleanup=%+v", s)
	}
	if err = observer.Close(); err != nil {
		t.Fatalf("second close=%v", err)
	}
}
