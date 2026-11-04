//go:build hid_diagnostics && integration

package hid

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/PeculiarVentures/fido-go/internal/diagnostics"
)

func identicalSnapshot(ctx context.Context, backend Backend) (Snapshot, error) {
	bus := BusUSB
	usage := Usage{Page: 0xf1d0, ID: 1}
	return backend.Enumerate(ctx, EnumerateOptions{Filter: Filter{Bus: &bus, Usage: &usage}})
}

func waitIdenticalInitial(ctx context.Context, scope *diagnostics.Scope, backend Backend, selected []EndpointID) (Snapshot, []Endpoint, error) {
	bounded, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	var incomplete uint64
	for {
		snapshot, err := identicalSnapshot(bounded, backend)
		if err != nil {
			return Snapshot{}, nil, err
		}
		if snapshot.Complete {
			pair, err := classifyIdenticalInitial(snapshot, selected)
			return snapshot, pair, err
		}
		incomplete++
		scope.Counter("initial_incomplete_polls", incomplete)
		select {
		case <-ticker.C:
		case <-bounded.Done():
			return Snapshot{}, nil, diagnostics.InconclusiveReason("no complete identical-key baseline inventory was observed")
		}
	}
}

type identicalPhaseDifference struct {
	snapshot       Snapshot
	removed, added []Endpoint
}

func waitIdenticalPhase(ctx context.Context, scope *diagnostics.Scope, backend Backend, before Snapshot, phase, removedCount, addedCount int, model Endpoint) (identicalPhaseDifference, error) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	prefix := fmt.Sprintf("phase_%d_", phase)
	var polls, incomplete uint64
	for {
		current, err := identicalSnapshot(ctx, backend)
		if err != nil {
			return identicalPhaseDifference{}, err
		}
		polls++
		scope.Counter(prefix+"inventory_polls", polls)
		if !current.Complete {
			incomplete++
			scope.Counter(prefix+"incomplete_polls", incomplete)
		} else {
			removed, added, err := classifyIdenticalDifference(before, current)
			if err != nil {
				scope.Counter("unexpected_inventory_change_count", 1)
				return identicalPhaseDifference{}, err
			}
			for _, endpoint := range added {
				if !sameIdenticalDescriptor(model, endpoint) {
					scope.Counter("unexpected_inventory_change_count", 1)
					return identicalPhaseDifference{}, diagnostics.InconclusiveReason("unexpected descriptor appeared during identical-key operator enrollment")
				}
			}
			if len(removed) == removedCount && len(added) == addedCount {
				scope.Counter(prefix+"before_count", uint64(len(before.Endpoints)))
				scope.Counter(prefix+"after_count", uint64(len(current.Endpoints)))
				scope.Counter(prefix+"removed_count", uint64(len(removed)))
				scope.Counter(prefix+"added_count", uint64(len(added)))
				for _, fact := range []string{"inventory_complete", "expected_difference", "operator_action_observed", "retained_addresses_unchanged"} {
					scope.Fact(prefix+fact, true)
				}
				return identicalPhaseDifference{snapshot: current, removed: removed, added: added}, nil
			}
			unchanged := len(removed) == 0 && len(added) == 0
			bothRemovalInProgress := phase == 5 && len(added) == 0 && len(removed) < removedCount
			if !unchanged && !bothRemovalInProgress {
				scope.Counter("unexpected_inventory_change_count", 1)
				return identicalPhaseDifference{}, diagnostics.InconclusiveReason("unexpected complete inventory change during identical-key operator enrollment")
			}
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return identicalPhaseDifference{}, errors.Join(diagnostics.InconclusiveReason("expected identical-key inventory transition was not observed within the phase budget"), ctx.Err())
		}
	}
}

func identicalOperatorPhase(ctx context.Context, scope *diagnostics.Scope, options hidDiagnosticsOptions, backend Backend, before Snapshot, phase, removed, added int, model Endpoint) (identicalPhaseDifference, error) {
	names := []string{"identical-unplug-a", "identical-replug-a", "identical-unplug-b", "identical-replug-b", "identical-unplug-both", "identical-insert-b-at-a-port", "identical-insert-a-at-b-port"}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if err := options.OperatorPrompt(bounded, diagnosticOperatorAction{Phase: names[phase-1], KeyCount: 2}); err != nil {
		return identicalPhaseDifference{}, err
	}
	scope.Counter("prompts_completed", uint64(phase))
	return waitIdenticalPhase(bounded, scope, backend, before, phase, removed, added, model)
}
