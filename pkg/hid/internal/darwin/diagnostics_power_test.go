//go:build darwin && cgo && hid_diagnostics

package darwin

import (
	"github.com/PeculiarVentures/fido-go/internal/diagnostics/power"
	"testing"
)

func TestDiagnosticsPowerReducerRequiresOneOrderedAcknowledgedCycle(t *testing.T) {
	const gen = uint64(7)
	event := func(kind PowerEventKind) PowerEvent { return PowerEvent{Kind: kind, ArmGeneration: gen} }
	good := []PowerEvent{event(PowerCanSleep), event(PowerWillSleep), event(PowerPoweredOn)}
	s := ReducePowerEvents(gen, good)
	if !s.Synthetic || !s.Matched || s.SleepEvents != 1 || s.WakeEvents != 1 || s.AckCount != 2 || s.AckErrors != 0 || s.WillSleepGeneration != gen || s.PoweredOnGeneration != gen || s.SleepSequence == 0 || s.WakeSequence <= s.SleepSequence {
		t.Fatalf("valid synthetic sequence=%+v", s)
	}
	stale := event(PowerWillSleep)
	stale.ArmGeneration = gen - 1
	badAck := event(PowerWillSleep)
	badAck.AckCode = 0xe00002bc
	cases := map[string][]PowerEvent{"wake first": {event(PowerPoweredOn), event(PowerWillSleep)}, "sleep only": {event(PowerWillSleep)}, "cancel": {event(PowerWillSleep), event(PowerWillNotSleep), event(PowerPoweredOn)}, "extra": append(append([]PowerEvent{}, good...), event(PowerWillSleep), event(PowerPoweredOn)), "stale": {stale, event(PowerWillSleep), event(PowerPoweredOn)}, "ack failure": {badAck, event(PowerPoweredOn)}}
	for name, events := range cases {
		t.Run(name, func(t *testing.T) {
			s := ReducePowerEvents(gen, events)
			if !s.Synthetic || s.Matched {
				t.Fatalf("invalid sequence qualified: %+v", s)
			}
			if name == "ack failure" && (s.AckErrors != 1 || s.NativeCode != 0xe00002bc) {
				t.Fatalf("ack failure lost: %+v", s)
			}
			if name == "stale" && s.StaleEvents != 1 {
				t.Fatalf("stale not recorded: %+v", s)
			}
		})
	}
	if s := ReducePowerEvents(0, nil); s.NativeCode == 0 || !s.Synthetic || s.Matched {
		t.Fatalf("zero generation accepted: %+v", s)
	}
	if s := ReducePowerEvents(gen, make([]PowerEvent, 257)); s.NativeCode == 0 || !s.Synthetic || s.Matched {
		t.Fatalf("oversized fixture accepted: %+v", s)
	}
}

func TestDiagnosticsPowerReducerMatchesSharedObserver(t *testing.T) {
	const gen uint64 = 31
	legacy := []PowerEvent{{Kind: PowerCanSleep, ArmGeneration: gen}, {Kind: PowerWillSleep, ArmGeneration: gen}, {Kind: PowerPoweredOn, ArmGeneration: gen}}
	shared := []power.Event{{Kind: power.CanSleep, ArmGeneration: gen}, {Kind: power.WillSleep, ArmGeneration: gen}, {Kind: power.PoweredOn, ArmGeneration: gen}}
	a, b := ReducePowerEvents(gen, legacy), power.ReduceEvents(gen, shared)
	if a != b || !a.Synthetic || !a.Matched {
		t.Fatalf("legacy/shared evidence differs: legacy=%+v shared=%+v", a, b)
	}
}
