//go:build hid_diagnostics && (!darwin || !cgo)

package power

import "context"

// Available reports whether this build has a native power observer.
func Available() bool { return false }

// Observer is unavailable without Darwin cgo support.
type Observer struct{}

// New reports unsupported without registering for native notifications.
func New() (*Observer, error) { return nil, unsupported() }

// Arm reports that native observation is unavailable.
func (*Observer) Arm() (uint64, error) { return 0, unsupported() }

// Snapshot contains no native evidence on an unsupported build.
func (*Observer) Snapshot() Snapshot { return Snapshot{} }

// WaitSleep reports that native observation is unavailable.
func (*Observer) WaitSleep(context.Context, uint64) (Snapshot, error) {
	return Snapshot{}, unsupported()
}

// Wait reports that native observation is unavailable.
func (*Observer) Wait(context.Context, uint64) (Snapshot, error) { return Snapshot{}, unsupported() }

// Close is harmless when no native resources could be acquired.
func (*Observer) Close() error { return nil }

// ReduceEvents cannot run the native reducer on this build. It never presents
// an unavailable fixture as a successful native or synthetic power cycle.
func ReduceEvents(uint64, []Event) Snapshot {
	return Snapshot{Synthetic: true, NativeCode: 0xe00002c7}
}

func unsupported() error {
	return failure("observe", KindUnsupported, "native power observation requires Darwin cgo")
}
