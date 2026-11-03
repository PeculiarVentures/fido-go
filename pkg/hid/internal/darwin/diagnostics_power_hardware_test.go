//go:build darwin && cgo && hid_diagnostics && integration

package darwin

import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestDiagnosticsPowerObserverRegistration(t *testing.T) {
	if os.Getenv("FIDO_HID_POWER_OBSERVER_TEST") != "1" {
		t.Skip("set FIDO_HID_POWER_OBSERVER_TEST=1 for read-only system power observer registration")
	}
	p, err := NewPowerObserver()
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	s := p.Snapshot()
	if !s.Ready || s.Synthetic || s.ObserverGeneration == 0 {
		t.Fatalf("observer registration=%+v", s)
	}
	gen, err := p.Arm()
	if err != nil || gen == 0 {
		t.Fatalf("arm=%d %v", gen, err)
	}
	s = p.Snapshot()
	if !s.Ready || !s.Armed || s.Synthetic || s.ArmGeneration != gen {
		t.Fatalf("armed observer=%+v", s)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = p.Wait(ctx, gen); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled wait=%v", err)
	}
	if err = p.Close(); err != nil {
		t.Fatal(err)
	}
	s = p.Snapshot()
	if !s.Closed || !s.ThreadJoined || !s.Released || s.Synthetic {
		t.Fatalf("observer cleanup=%+v", s)
	}
	if err = p.Close(); err != nil {
		t.Fatalf("repeated close=%v", err)
	}
}
