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

func TestDiagnosticsAttachWinsRetirement(t *testing.T) {
	d := newFake("diagnostic-attach-before-retire")
	c := openFake(t, d)
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	type answer struct {
		unlocked, freed bool
		err             error
	}
	attached := make(chan answer, 1)
	go func() {
		a := answer{}
		a.err = withDiagnosticDevice(c, func(dev driver.Device) error {
			if dev != d {
				return errors.New("wrong device")
			}
			if c.(*connection).mu.TryLock() {
				a.unlocked = true
				c.(*connection).mu.Unlock()
			}
			close(entered)
			<-release
			select {
			case <-d.closed:
				a.freed = true
			default:
			}
			return nil
		})
		attached <- a
	}()
	waitLifecycleTestSignal(t, entered)
	started := make(chan struct{})
	closed := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go func() { close(started); closed <- c.Close(ctx) }()
	waitLifecycleTestSignal(t, started)
	releaseOnce.Do(func() { close(release) })
	select {
	case a := <-attached:
		if a.err != nil || a.unlocked || a.freed {
			t.Fatalf("attachment lost ownership: %+v", a)
		}
	case <-ctx.Done():
		t.Fatal("attachment did not finish")
	}
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("retirement did not finish")
	}
	waitLifecycleTestSignal(t, d.closed)
}
func TestDiagnosticsRetirementWinsAttach(t *testing.T) {
	d := newFake("diagnostic-retire-before-attach")
	c := openFake(t, d)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = c.Close(ctx)
	called := false
	err := withDiagnosticDevice(c, func(driver.Device) error { called = true; return nil })
	if !errors.Is(err, ErrClosed) || called {
		t.Fatalf("retired attachment err=%v callback=%v", err, called)
	}
}
