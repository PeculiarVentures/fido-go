//go:build darwin && cgo && hid_diagnostics

package darwin

import (
	"context"
	"errors"

	"github.com/PeculiarVentures/fido-go/internal/diagnostics/power"
	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/driver"
)

// PowerSnapshot preserves the original HID harness evidence API.
type PowerSnapshot = power.Snapshot

// PowerEventKind preserves the native reducer fixture API.
type PowerEventKind = power.EventKind

const (
	PowerCanSleep     = power.CanSleep
	PowerWillSleep    = power.WillSleep
	PowerPoweredOn    = power.PoweredOn
	PowerWillNotSleep = power.WillNotSleep
)

// PowerEvent preserves the original synthetic event shape.
type PowerEvent = power.Event

// PowerObserver adapts shared diagnostic infrastructure to the legacy internal
// HID error contract. There is exactly one native observer implementation.
type PowerObserver struct{ observer *power.Observer }

// NewPowerObserver registers through the shared diagnostic power package.
func NewPowerObserver() (*PowerObserver, error) {
	observer, err := power.New()
	if err != nil {
		return nil, translatePowerError(err)
	}
	return &PowerObserver{observer: observer}, nil
}

// Arm starts a new native observation generation.
func (p *PowerObserver) Arm() (uint64, error) {
	if p.observer == nil {
		return 0, failure("power observer arm", driver.KindClosed, "observer closed")
	}
	generation, err := p.observer.Arm()
	return generation, translatePowerError(err)
}

// Snapshot copies shared evidence, including after Close.
func (p *PowerObserver) Snapshot() PowerSnapshot {
	if p.observer == nil {
		return PowerSnapshot{}
	}
	return p.observer.Snapshot()
}

// Wait observes a complete ordered sleep/wake cycle for the generation.
func (p *PowerObserver) Wait(ctx context.Context, generation uint64) (PowerSnapshot, error) {
	if p.observer == nil {
		return p.uninitializedWait(ctx, generation)
	}
	snapshot, err := p.observer.Wait(ctx, generation)
	return snapshot, translatePowerError(err)
}

// WaitSleep observes the native sleep phase for the generation.
func (p *PowerObserver) WaitSleep(ctx context.Context, generation uint64) (PowerSnapshot, error) {
	if p.observer == nil {
		return p.uninitializedWait(ctx, generation)
	}
	snapshot, err := p.observer.WaitSleep(ctx, generation)
	return snapshot, translatePowerError(err)
}

func (p *PowerObserver) uninitializedWait(ctx context.Context, generation uint64) (PowerSnapshot, error) {
	if ctx == nil || generation == 0 {
		return PowerSnapshot{}, failure("power observer wait", driver.KindInvalidArgument, "context and arm generation are required")
	}
	if err := ctx.Err(); err != nil {
		return PowerSnapshot{}, err
	}
	return PowerSnapshot{}, failure("power observer wait", driver.KindClosed, "observer closed")
}

// Close joins cleanup while retaining legacy structured errors.
func (p *PowerObserver) Close() error {
	if p.observer == nil {
		return nil
	}
	return translatePowerError(p.observer.Close())
}

// ReducePowerEvents delegates to the single shared native reducer.
func ReducePowerEvents(generation uint64, events []PowerEvent) PowerSnapshot {
	return power.ReduceEvents(generation, events)
}

func translatePowerError(err error) error {
	if err == nil {
		return nil
	}
	if native, ok := err.(*power.Error); ok {
		kind := driver.KindIO
		switch native.Kind {
		case power.KindClosed:
			kind = driver.KindClosed
		case power.KindRemoved:
			kind = driver.KindRemoved
		case power.KindPermission:
			kind = driver.KindPermission
		case power.KindBusy:
			kind = driver.KindBusy
		case power.KindUnsupported:
			kind = driver.KindUnsupported
		case power.KindInvalidArgument:
			kind = driver.KindInvalidArgument
		case power.KindResourceLimit:
			kind = driver.KindResourceLimit
		}
		return &driver.Error{Op: native.Op, Kind: kind, Domain: native.Domain, Code: native.Code, Message: native.Message, Cause: translatePowerError(native.Cause)}
	}
	if many, ok := err.(interface{ Unwrap() []error }); ok {
		causes := many.Unwrap()
		translated := make([]error, len(causes))
		for index, cause := range causes {
			translated[index] = translatePowerError(cause)
		}
		return errors.Join(translated...)
	}
	return err
}
