//go:build hid_diagnostics

// Package power provides diagnostic-only native power observation, independent
// of HID and USB transports. It never initiates sleep or vetoes power changes.
package power

// Snapshot contains native observation evidence for one armed cycle.
// Sequence and event counts are scoped to ArmGeneration. Ready records the
// registration handshake; Released and ThreadJoined record completed teardown.
type Snapshot struct {
	ObserverGeneration, ArmGeneration, WillSleepGeneration, PoweredOnGeneration uint64
	SleepSequence, WakeSequence                                                 uint64
	CanSleepEvents, SleepEvents, WakeEvents, CanceledEvents                     uint64
	OutOfOrderEvents, ExtraCycleEvents, StaleEvents, AckCount, AckErrors        uint64
	NativeCode, DeregisterCode, ServiceCloseCode                                uint32
	Ready, Armed, Matched, Closed, ThreadJoined, Released, Synthetic            bool
}

// EventKind identifies a deterministic reducer fixture event.
type EventKind uint8

const (
	CanSleep EventKind = iota + 1
	WillSleep
	PoweredOn
	WillNotSleep
)

// Event is a synthetic reducer input. AckCode is used only for CanSleep
// and WillSleep. No fixture input can be delivered to a live observer.
type Event struct {
	Kind          EventKind
	ArmGeneration uint64
	AckCode       uint32
}
