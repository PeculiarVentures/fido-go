//go:build darwin && cgo && hid_diagnostics

package power

/*
#cgo CFLAGS: -DPOWER_DIAGNOSTICS=1 -Wall -Wextra
#cgo LDFLAGS: -framework IOKit -framework CoreFoundation
#include "power_native.h"
#include <IOKit/IOReturn.h>
#include <mach/mach_error.h>
#include <errno.h>
*/
import "C"

import (
	"context"
	"errors"
	"sync"
	"syscall"
)

// Observer owns a native runloop thread and a system power registration.
// It only observes events and promptly acknowledges required notifications.
// It never initiates sleep, creates assertions, or vetoes a power change.
type Observer struct {
	mu     sync.Mutex
	native *C.diagnostic_power_observer
	last   Snapshot
}

// Available reports whether this build has a native power observer.
func Available() bool { return true }

// New returns after the owner thread has registered and scheduled its source.
// Every callback and its context remain native-owned.
func New() (*Observer, error) {
	var threadError C.int
	var nativeError C.uint32_t
	native := C.diagnostic_power_new(&threadError, &nativeError)
	if native == nil {
		return nil, pthreadError("power observer create", threadError)
	}
	p := &Observer{native: native}
	if nativeError != 0 {
		return nil, errors.Join(ioError("power observer register", nativeError), p.Close())
	}
	return p, nil
}

// Arm rotates registration on its native owner thread, discarding the previous
// notification source before establishing a new generation. Thus queued events
// from a prior registration cannot qualify the new cycle.
func (p *Observer) Arm() (uint64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.native == nil {
		return 0, failure("power observer arm", KindClosed, "observer closed")
	}
	var generation C.uint64_t
	var nativeError C.uint32_t
	code := C.diagnostic_power_arm(p.native, &generation, &nativeError)
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
func (p *Observer) Snapshot() Snapshot {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.snapshotLocked()
}

func (p *Observer) snapshotLocked() Snapshot {
	if p.native != nil {
		var native C.diagnostic_power_snapshot
		C.diagnostic_power_snapshot_read(p.native, &native)
		p.last = publicSnapshot(native)
	}
	return p.last
}

// Wait waits for exactly one post-arm SystemWillSleep -> SystemHasPoweredOn
// pair. Canceled, stale, extra, or out-of-order events fail qualification.
func (p *Observer) Wait(ctx context.Context, generation uint64) (Snapshot, error) {
	return p.wait(ctx, generation, false)
}

// WaitSleep waits for the post-arm SystemWillSleep phase, allowing the caller
// to use separate bounded budgets for initiating sleep and observing wakeup.
func (p *Observer) WaitSleep(ctx context.Context, generation uint64) (Snapshot, error) {
	return p.wait(ctx, generation, true)
}

func (p *Observer) wait(ctx context.Context, generation uint64, sleepOnly bool) (Snapshot, error) {
	if ctx == nil || generation == 0 {
		return Snapshot{}, failure("power observer wait", KindInvalidArgument, "context and arm generation are required")
	}
	for {
		if err := ctx.Err(); err != nil {
			return p.Snapshot(), err
		}
		p.mu.Lock()
		if p.native == nil {
			snapshot := p.last
			p.mu.Unlock()
			return snapshot, failure("power observer wait", KindClosed, "observer closed")
		}
		code := C.diagnostic_power_wait(p.native, C.uint64_t(generation), cbool(sleepOnly), 20)
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
		kind := KindIO
		if code == C.EINVAL {
			kind = KindInvalidArgument
		} else if code == C.ECANCELED {
			kind = KindClosed
		}
		return snapshot, failure("power observer wait", kind, "power event sequence did not qualify for the armed generation")
	}
}

// Close idempotently stops the native loop, unregisters callbacks, destroys its
// notification port, closes the root service, and joins before freeing storage.
func (p *Observer) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.native == nil {
		return powerCleanupError(p.last)
	}
	var snapshot C.diagnostic_power_snapshot
	if code := C.diagnostic_power_close(p.native, &snapshot); code != 0 {
		// Keep ownership if the thread could not be joined; no native free occurred.
		return pthreadError("power observer join", code)
	}
	p.last = publicSnapshot(snapshot)
	p.native = nil
	return powerCleanupError(p.last)
}

func powerCleanupError(snapshot Snapshot) error {
	var causes []error
	if snapshot.DeregisterCode != 0 {
		causes = append(causes, ioError("power observer deregister", C.uint32_t(snapshot.DeregisterCode)))
	}
	if snapshot.ServiceCloseCode != 0 {
		causes = append(causes, ioError("power observer service close", C.uint32_t(snapshot.ServiceCloseCode)))
	}
	return errors.Join(causes...)
}

func publicSnapshot(s C.diagnostic_power_snapshot) Snapshot {
	return Snapshot{
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

// ReduceEvents runs the callback's actual native reducer without registering
// for power notifications. Its snapshot is always Synthetic and cannot qualify
// an actual sleep/wake scenario. At most 256 fixture events are accepted.
func ReduceEvents(generation uint64, events []Event) Snapshot {
	var native C.diagnostic_power_snapshot
	native.synthetic = 1
	native.observer_generation = 1
	native.arm_generation = C.uint64_t(generation)
	if generation == 0 || len(events) > 256 {
		native.native_code = C.uint32_t(0xe00002c2)
		return publicSnapshot(native)
	}
	native.ready, native.armed = 1, 1
	for _, event := range events {
		C.diagnostic_power_reduce(&native, C.uint64_t(event.ArmGeneration), C.int(event.Kind), C.uint32_t(event.AckCode))
	}
	return publicSnapshot(native)
}

func cbool(value bool) C.int {
	if value {
		return 1
	}
	return 0
}

func pthreadError(op string, code C.int) error {
	return &Error{Op: op, Kind: KindIO, Domain: "pthread", Code: uint64(code), Message: syscall.Errno(code).Error()}
}

func ioError(op string, code C.uint32_t) error {
	kind := KindIO
	switch int32(code) {
	case C.kIOReturnNoDevice, C.kIOReturnOffline:
		kind = KindRemoved
	case C.kIOReturnNotPrivileged, C.kIOReturnNotPermitted:
		kind = KindPermission
	case C.kIOReturnExclusiveAccess, C.kIOReturnBusy:
		kind = KindBusy
	case C.kIOReturnUnsupported:
		kind = KindUnsupported
	case C.kIOReturnNoMemory, C.kIOReturnNoResources:
		kind = KindResourceLimit
	case C.kIOReturnNotOpen:
		kind = KindClosed
	}
	return &Error{Op: op, Kind: kind, Domain: "iokit", Code: uint64(code), Message: C.GoString(C.mach_error_string(C.mach_error_t(code)))}
}
