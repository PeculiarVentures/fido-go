//go:build darwin && cgo && hid_diagnostics

package darwin

/*
#include "power_diagnostics.h"
#include <errno.h>
*/
import "C"

import (
	"context"
	"errors"
	"sync"

	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/driver"
)

// PowerSnapshot contains native observation evidence for one armed cycle.
// Sequence and event counts are scoped to ArmGeneration. Ready records the
// registration handshake; Released and ThreadJoined record completed teardown.
type PowerSnapshot struct {
	ObserverGeneration, ArmGeneration, WillSleepGeneration, PoweredOnGeneration uint64
	SleepSequence, WakeSequence                                                 uint64
	CanSleepEvents, SleepEvents, WakeEvents, CanceledEvents                     uint64
	OutOfOrderEvents, ExtraCycleEvents, StaleEvents, AckCount, AckErrors        uint64
	NativeCode, DeregisterCode, ServiceCloseCode                                uint32
	Ready, Armed, Matched, Closed, ThreadJoined, Released, Synthetic            bool
}

// PowerObserver owns a native runloop thread and a system power registration.
// It only observes events and promptly acknowledges required notifications.
// It never initiates sleep, creates assertions, or vetoes a power change.
type PowerObserver struct {
	mu     sync.Mutex
	native *C.hid_power_observer
	last   PowerSnapshot
}

// NewPowerObserver returns after the owner thread has registered and scheduled
// its notification source. Every callback and its context remain native-owned.
func NewPowerObserver() (*PowerObserver, error) {
	var threadError C.int
	var nativeError C.uint32_t
	native := C.hid_power_new(&threadError, &nativeError)
	if native == nil {
		return nil, pthreadError("power observer create", threadError)
	}
	p := &PowerObserver{native: native}
	if nativeError != 0 {
		return nil, errors.Join(ioError("power observer register", nativeError), p.Close())
	}
	return p, nil
}

// Arm rotates registration on its native owner thread, discarding the previous
// notification source before establishing a new generation. Thus queued events
// from a prior registration cannot qualify the new cycle.
func (p *PowerObserver) Arm() (uint64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.native == nil {
		return 0, failure("power observer arm", driver.KindClosed, "observer closed")
	}
	var generation C.uint64_t
	var nativeError C.uint32_t
	code := C.hid_power_arm(p.native, &generation, &nativeError)
	if nativeError != 0 {
		return 0, ioError("power observer arm", nativeError)
	}
	if code != 0 {
		return 0, pthreadError("power observer arm", code)
	}
	return uint64(generation), nil
}

// Snapshot returns an independent copy, including after Close. Concurrent Close
// cannot free native storage while another Go method is using it.
func (p *PowerObserver) Snapshot() PowerSnapshot {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.snapshotLocked()
}

func (p *PowerObserver) snapshotLocked() PowerSnapshot {
	if p.native != nil {
		var native C.hid_power_snapshot
		C.hid_power_snapshot_read(p.native, &native)
		p.last = publicPowerSnapshot(native)
	}
	return p.last
}

// Wait waits for exactly one post-arm SystemWillSleep -> SystemHasPoweredOn
// pair. Canceled, stale, extra, or out-of-order events fail qualification.
func (p *PowerObserver) Wait(ctx context.Context, generation uint64) (PowerSnapshot, error) {
	return p.wait(ctx, generation, false)
}

// WaitSleep waits for the post-arm SystemWillSleep phase, allowing the caller
// to use separate bounded budgets for initiating sleep and observing wakeup.
func (p *PowerObserver) WaitSleep(ctx context.Context, generation uint64) (PowerSnapshot, error) {
	return p.wait(ctx, generation, true)
}

func (p *PowerObserver) wait(ctx context.Context, generation uint64, sleepOnly bool) (PowerSnapshot, error) {
	if ctx == nil || generation == 0 {
		return PowerSnapshot{}, failure("power observer wait", driver.KindInvalidArgument, "context and arm generation are required")
	}
	for {
		if err := ctx.Err(); err != nil {
			return p.Snapshot(), err
		}
		p.mu.Lock()
		if p.native == nil {
			snapshot := p.last
			p.mu.Unlock()
			return snapshot, failure("power observer wait", driver.KindClosed, "observer closed")
		}
		code := C.hid_power_wait(p.native, C.uint64_t(generation), cbool(sleepOnly), 20)
		snapshot := p.snapshotLocked()
		p.mu.Unlock()
		if code == 0 {
			return snapshot, nil
		}
		if code == C.ETIMEDOUT {
			continue
		}
		if snapshot.NativeCode != 0 {
			return snapshot, ioError("power observer wait", C.uint32_t(snapshot.NativeCode))
		}
		kind := driver.KindIO
		if code == C.EINVAL {
			kind = driver.KindInvalidArgument
		} else if code == C.ECANCELED {
			kind = driver.KindClosed
		}
		return snapshot, failure("power observer wait", kind, "power event sequence did not qualify for the armed generation")
	}
}

// Close idempotently stops the native loop, unregisters callbacks, destroys its
// notification port, closes the root service, and joins before freeing storage.
func (p *PowerObserver) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.native == nil {
		return powerCleanupError(p.last)
	}
	var snapshot C.hid_power_snapshot
	if code := C.hid_power_close(p.native, &snapshot); code != 0 {
		// Keep ownership if the thread could not be joined; no native free occurred.
		return pthreadError("power observer join", code)
	}
	p.last = publicPowerSnapshot(snapshot)
	p.native = nil
	return powerCleanupError(p.last)
}

func powerCleanupError(snapshot PowerSnapshot) error {
	var causes []error
	if snapshot.DeregisterCode != 0 {
		causes = append(causes, ioError("power observer deregister", C.uint32_t(snapshot.DeregisterCode)))
	}
	if snapshot.ServiceCloseCode != 0 {
		causes = append(causes, ioError("power observer service close", C.uint32_t(snapshot.ServiceCloseCode)))
	}
	return errors.Join(causes...)
}

func publicPowerSnapshot(s C.hid_power_snapshot) PowerSnapshot {
	return PowerSnapshot{
		ObserverGeneration: uint64(s.observer_generation), ArmGeneration: uint64(s.arm_generation),
		WillSleepGeneration: uint64(s.will_sleep_generation), PoweredOnGeneration: uint64(s.powered_on_generation),
		SleepSequence: uint64(s.sleep_sequence), WakeSequence: uint64(s.wake_sequence),
		CanSleepEvents: uint64(s.can_sleep_events), SleepEvents: uint64(s.sleep_events), WakeEvents: uint64(s.wake_events), CanceledEvents: uint64(s.canceled_events),
		OutOfOrderEvents: uint64(s.out_of_order_events), ExtraCycleEvents: uint64(s.extra_cycle_events), StaleEvents: uint64(s.stale_events), AckCount: uint64(s.ack_count), AckErrors: uint64(s.ack_errors),
		NativeCode: uint32(s.native_code), DeregisterCode: uint32(s.deregister_code), ServiceCloseCode: uint32(s.service_close_code),
		Ready: s.ready != 0, Armed: s.armed != 0, Matched: s.matched != 0, Closed: s.closed != 0,
		ThreadJoined: s.thread_joined != 0, Released: s.released != 0, Synthetic: s.synthetic != 0,
	}
}

// PowerEventKind identifies a deterministic reducer fixture event.
type PowerEventKind uint8

const (
	PowerCanSleep PowerEventKind = iota + 1
	PowerWillSleep
	PowerPoweredOn
	PowerWillNotSleep
)

// PowerEvent is a synthetic reducer input. AckCode is used only for CanSleep
// and WillSleep. No fixture input can be delivered to a live observer.
type PowerEvent struct {
	Kind          PowerEventKind
	ArmGeneration uint64
	AckCode       uint32
}

// ReducePowerEvents runs the callback's actual native reducer without registering
// for power notifications. Its snapshot is always Synthetic and cannot qualify
// an actual sleep/wake scenario. At most 256 fixture events are accepted.
func ReducePowerEvents(generation uint64, events []PowerEvent) PowerSnapshot {
	var native C.hid_power_snapshot
	native.synthetic = 1
	native.observer_generation = 1
	native.arm_generation = C.uint64_t(generation)
	if generation == 0 || len(events) > 256 {
		native.native_code = C.uint32_t(0xe00002c2)
		return publicPowerSnapshot(native)
	}
	native.ready, native.armed = 1, 1
	for _, event := range events {
		C.hid_power_reduce(&native, C.uint64_t(event.ArmGeneration), C.int(event.Kind), C.uint32_t(event.AckCode))
	}
	return publicPowerSnapshot(native)
}
