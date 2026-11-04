//go:build hid_diagnostics && (!darwin || !cgo)

package power_test

import (
	"errors"
	"github.com/PeculiarVentures/fido-go/internal/diagnostics/power"
	"testing"
)

func TestUnavailablePowerObserverCannotQualify(t *testing.T) {
	if power.Available() {
		t.Fatal("unsupported observer advertised available")
	}
	observer, err := power.New()
	var native *power.Error
	if observer != nil || !errors.As(err, &native) || native.Kind != power.KindUnsupported {
		t.Fatalf("observer=%v err=%v", observer, err)
	}
	s := power.ReduceEvents(1, nil)
	if !s.Synthetic || s.Matched {
		t.Fatalf("unavailable fixture qualified: %+v", s)
	}
}
