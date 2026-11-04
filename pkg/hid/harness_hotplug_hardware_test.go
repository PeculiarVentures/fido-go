//go:build hid_diagnostics && integration

package hid

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"time"

	"github.com/PeculiarVentures/fido-go/internal/diagnostics"
)

func hardwareHotplugRun(options hidDiagnosticsOptions) diagnosticRun {
	return diagnosticRun{id: "hardware.unplug-replug", run: func(ctx context.Context, scope *diagnostics.Scope) (runErr error) {
		defer func() { runErr = diagnosticSafeError(scope, runErr) }()
		if options.OperatorPrompt == nil {
			return diagnostics.InconclusiveReason("interactive physical unplug/replug requires a bounded operator callback")
		}
		selected, err := diagnosticHardwareEndpoints(ctx, options.EndpointIDs)
		if err != nil {
			return err
		}
		scope.Counter(diagnosticKeysSelected, uint64(len(selected)))
		if len(selected) == 0 {
			return diagnostics.InconclusiveReason("no selected USB FIDO endpoint is available")
		}
		scope.Fact("physical_identity_proven", false)
		scope.Fact("manual_same_port_reconnect_requested", true)
		scope.Fact("requests_replayed", false)
		for index, endpoint := range selected {
			if err = diagnosePhysicalHotplug(ctx, scope, options, endpoint, index+1); err != nil {
				return err
			}
			scope.Counter(diagnosticKeysCompleted, uint64(index+1))
		}
		for _, fact := range []string{"all_absences_complete", "all_stale_exact_opens_rejected", "all_neighbors_ping_verified", "all_recoveries_ping_verified"} {
			scope.Fact(fact, true)
		}
		return nil
	}}
}

func diagnosePhysicalHotplug(ctx context.Context, scope *diagnostics.Scope, options hidDiagnosticsOptions, target Endpoint, ordinal int) error {
	prefix := diagnosticKeyPrefix(uint64(ordinal))
	baseline, err := diagnosticHardwareEndpoints(ctx, nil)
	if err != nil {
		return err
	}
	if len(baseline) < 2 {
		return diagnostics.InconclusiveReason("physical hotplug requires a surviving USB FIDO neighbor")
	}
	if !target.VendorID.Known || !target.ProductID.Known || !target.Usage.Known {
		return diagnostics.InconclusiveReason("selected hotplug target lacks known model metadata")
	}
	neighbors := make([]Endpoint, 0, len(baseline)-1)
	targetPresent := false
	for _, endpoint := range baseline {
		if endpoint.ID == target.ID {
			targetPresent = true
			if !sameRecoveryDescriptor(target, endpoint) {
				return diagnostics.InconclusiveReason("selected target descriptor changed before the operator phase")
			}
			continue
		}
		// Model metadata selects a recovery candidate only within this observed
		// inventory. It never establishes durable or cryptographic identity.
		if sameRecoveryDescriptor(target, endpoint) {
			return diagnostics.InconclusiveReason("hotplug recovery is ambiguous among matching model descriptors")
		}
		neighbors = append(neighbors, endpoint)
	}
	if !targetPresent {
		return diagnostics.InconclusiveReason("selected exact target is absent before the operator phase")
	}
	closePolicy := &hotplugClosePolicy{scope: scope, prefix: prefix}
	old, cid, err := openDiagnosticChannelWithCleanup(ctx, scope, target, closePolicy.cleanup)
	if err != nil {
		return err
	}
	if err = closePolicy.attach(old); err != nil {
		return err
	}
	readCtx, cancelRead := context.WithCancel(ctx)
	readDone := make(chan struct{})
	var readErr error
	go func() { _, readErr = old.Read(readCtx, 0); close(readDone) }()
	defer func() { cancelRead(); <-readDone }()
	if err = observeHotplugReadAdmission(ctx, old, readDone); err != nil {
		return err
	}
	scope.Fact(prefix+"old_read_admitted", true)
	if err = promptPhysicalHotplug(ctx, options, target, ordinal, "unplug"); err != nil {
		return err
	}
	_, err = waitPhysicalHotplugInventory(ctx, scope, prefix+"unplug_", target, neighbors, false)
	if err != nil {
		return err
	}
	scope.Fact(prefix+"absence_complete", true)
	closePolicy.absenceComplete = true
	responseCtx, cancelResponse := context.WithTimeout(ctx, 2*time.Second)
	err = waitDiagnosticSignal(responseCtx, readDone)
	cancelResponse()
	if err != nil {
		return diagnostics.InconclusiveReason("old physical read did not report removal within its bounded observation")
	}
	if readErr == nil || errors.Is(readErr, context.Canceled) || errors.Is(readErr, context.DeadlineExceeded) {
		return errors.New("old physical read did not produce an unplug-related error")
	}
	scope.Fact(prefix+"old_connection_error_observed", true)
	scope.Fact(prefix+"native_removal_error", errors.Is(readErr, ErrRemoved))
	closePolicy.removalObserved = errors.Is(readErr, ErrRemoved)
	closeCtx, cancelClose := context.WithTimeout(ctx, 2*time.Second)
	err = closePolicy.close(closeCtx, old)
	cancelClose()
	if err != nil {
		return err
	}
	if err = assertSupplementalRetired(ctx, old, cid); err != nil {
		return err
	}
	scope.Fact(prefix+"old_connection_closed", true)
	// Resolve the exact old address while a complete inventory says it is
	// absent. Never substitute a surviving VID/PID match or an earlier path.
	openCtx, cancelOpen := context.WithTimeout(ctx, 2*time.Second)
	stale, staleErr := New().Open(openCtx, target)
	cancelOpen()
	if stale != nil {
		closeCtx, cancelClose = context.WithTimeout(ctx, 2*time.Second)
		closeErr := stale.Close(closeCtx)
		cancelClose()
		return errors.Join(errors.New("exact stale endpoint opened during confirmed absence"), closeErr)
	}
	if !qualifiesStaleExactOpenRejection(staleErr) {
		return errors.Join(diagnostics.InconclusiveReason("stale exact Open did not confirm removal or a stale endpoint during confirmed absence"), staleErr)
	}
	scope.Fact(prefix+"stale_exact_open_rejected", true)
	for _, neighbor := range neighbors {
		bounded, cancel := context.WithTimeout(ctx, 8*time.Second)
		conn, neighborCID, err := openDiagnosticChannel(bounded, scope, neighbor)
		if err == nil {
			err = supplementalFreshPing(bounded, conn, neighborCID)
		}
		if conn != nil {
			err = errors.Join(err, conn.Close(bounded))
		}
		cancel()
		if err != nil {
			return err
		}
	}
	scope.Counter(prefix+"neighbors_verified", uint64(len(neighbors)))
	scope.Fact(prefix+"neighbors_ping_verified", true)
	// Recheck absence and neighbors after their probes, before asking for the
	// same physical key to be reconnected manually to its original port.
	if _, err = waitPhysicalHotplugInventory(ctx, scope, prefix+"unplug_recheck_", target, neighbors, false); err != nil {
		return err
	}
	if err = promptPhysicalHotplug(ctx, options, target, ordinal, "replug"); err != nil {
		return err
	}
	recovered, err := waitPhysicalHotplugInventory(ctx, scope, prefix+"replug_", target, neighbors, true)
	if err != nil {
		return err
	}
	scope.Fact(prefix+"reappearance_complete", true)
	scope.Fact(prefix+"unique_observed_descriptor_recovery", true)
	scope.Fact(prefix+"physical_identity_proven", false)
	bounded, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	fresh, freshCID, err := openDiagnosticChannel(bounded, scope, recovered)
	if err != nil {
		return err
	}
	if err = supplementalFreshPing(bounded, fresh, freshCID); err != nil {
		return err
	}
	scope.Fact(prefix+"fresh_init_ping_verified", true)
	return fresh.Close(bounded)
}

// A failed admission or unrelated native failure does not prove that the exact
// endpoint lookup rejected the stale address. Preserve that distinction even
// when the complete inventory independently observed the endpoint's absence.
func qualifiesStaleExactOpenRejection(err error) bool {
	return errors.Is(err, ErrRemoved) || errors.Is(err, ErrStaleEndpoint)
}

func promptPhysicalHotplug(ctx context.Context, options hidDiagnosticsOptions, target Endpoint, ordinal int, phase string) error {
	bounded, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	// The operator callback must honor this context. It receives no path,
	// endpoint selector, serial, or report bytes and runs without detached work.
	if err := options.OperatorPrompt(bounded, diagnosticOperatorAction{
		Phase: phase, KeyOrdinal: ordinal, VendorID: target.VendorID.Value, ProductID: target.ProductID.Value,
	}); err != nil {
		return err
	}
	return bounded.Err()
}

func waitPhysicalHotplugInventory(ctx context.Context, scope *diagnostics.Scope, prefix string, target Endpoint, neighbors []Endpoint, reappearing bool) (Endpoint, error) {
	bounded, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		bus, usage := BusUSB, (Usage{Page: 0xf1d0, ID: 1})
		snapshot, err := New().Enumerate(bounded, EnumerateOptions{Filter: Filter{Bus: &bus, Usage: &usage}})
		if err != nil {
			return Endpoint{}, err
		}
		// A transient incomplete scan during removal or arrival is neither
		// absence nor recovery evidence. Wait for a complete observation.
		if !snapshot.Complete {
			select {
			case <-bounded.Done():
				return Endpoint{}, diagnostics.InconclusiveReason("no complete physical inventory was observed within the operator phase")
			case <-ticker.C:
				continue
			}
		}
		current := snapshot.Endpoints
		scope.Counter(prefix+"snapshot_count", uint64(len(current)))
		scope.Counter(prefix+"expected_neighbor_count", uint64(len(neighbors)))
		scope.Counter(prefix+"target_vidpid_count", uint64(classifyHotplugNeighbor(target, current).VIDPIDCount))
		remaining := make([]Endpoint, 0, 1)
		for index, expected := range neighbors {
			evidence := classifyHotplugNeighbor(expected, current)
			recordHotplugNeighbor(scope, fmt.Sprintf("%sneighbor_%d_", prefix, index+1), expected, evidence)
			if !evidence.ExactMatch {
				reason := "unrelated neighbor's expected address and model are absent during the manual hotplug phase"
				switch {
				case evidence.SameIDDescriptorMismatch:
					reason = "unrelated neighbor retained its address but changed descriptor metadata during the manual hotplug phase"
				case evidence.SameDescriptorNewID:
					reason = "unrelated neighbor has matching descriptor metadata under a different address during the manual hotplug phase"
				case evidence.VIDPIDCount > 0:
					reason = "unrelated neighbor's address is absent while its model remains with different descriptor metadata during the manual hotplug phase"
				}
				return Endpoint{}, diagnostics.InconclusiveReason(reason)
			}
		}
		for _, endpoint := range current {
			neighbor := false
			for _, expected := range neighbors {
				if endpoint.ID == expected.ID {
					neighbor = true
					break
				}
			}
			if !neighbor {
				remaining = append(remaining, endpoint)
			}
		}
		if len(remaining) > 1 {
			return Endpoint{}, diagnostics.InconclusiveReason("additional or ambiguous endpoint appeared during the manual hotplug phase")
		}
		if len(remaining) == 1 {
			candidate := remaining[0]
			if !sameRecoveryDescriptor(target, candidate) || (!reappearing && candidate.ID != target.ID) {
				return Endpoint{}, diagnostics.InconclusiveReason("unexpected endpoint changed during the manual hotplug phase")
			}
			if reappearing {
				return candidate, nil
			}
		} else if !reappearing {
			return Endpoint{}, nil
		}
		select {
		case <-bounded.Done():
			return Endpoint{}, bounded.Err()
		case <-ticker.C:
		}
	}
}

// This evidence compares only the current complete inventory. A matching model
// or descriptor under another address never substitutes for an exact neighbor.
type hotplugNeighborEvidence struct {
	ExactMatch, SameIDPresent, SameIDDescriptorMismatch, SameDescriptorNewID bool
	VIDPIDCount, DescriptorCount                                             int
	VIDPIDChanged, UsageChanged, InterfaceChanged, BusChanged                bool
}

func classifyHotplugNeighbor(expected Endpoint, current []Endpoint) hotplugNeighborEvidence {
	var evidence hotplugNeighborEvidence
	for _, actual := range current {
		if expected.VendorID.Known && actual.VendorID.Known && expected.VendorID.Value == actual.VendorID.Value &&
			expected.ProductID.Known && actual.ProductID.Known && expected.ProductID.Value == actual.ProductID.Value {
			evidence.VIDPIDCount++
		}
		matches := sameRecoveryDescriptor(expected, actual)
		if matches {
			evidence.DescriptorCount++
			if actual.ID != expected.ID {
				evidence.SameDescriptorNewID = true
			}
		}
		if actual.ID != expected.ID {
			continue
		}
		evidence.SameIDPresent = true
		if matches {
			evidence.ExactMatch = true
		} else {
			evidence.SameIDDescriptorMismatch = true
			evidence.VIDPIDChanged = expected.VendorID != actual.VendorID || expected.ProductID != actual.ProductID
			evidence.UsageChanged = expected.Usage != actual.Usage
			evidence.InterfaceChanged = expected.Interface != actual.Interface
			evidence.BusChanged = expected.Bus != actual.Bus
		}
	}
	return evidence
}

func recordHotplugNeighbor(scope *diagnostics.Scope, prefix string, expected Endpoint, evidence hotplugNeighborEvidence) {
	if expected.VendorID.Known {
		scope.Counter(prefix+"expected_vendor_id", uint64(expected.VendorID.Value))
	}
	if expected.ProductID.Known {
		scope.Counter(prefix+"expected_product_id", uint64(expected.ProductID.Value))
	}
	scope.Counter(prefix+"vidpid_count", uint64(evidence.VIDPIDCount))
	scope.Counter(prefix+"descriptor_count", uint64(evidence.DescriptorCount))
	scope.Fact(prefix+"exact_match", evidence.ExactMatch)
	scope.Fact(prefix+"same_id_present", evidence.SameIDPresent)
	scope.Fact(prefix+"same_id_descriptor_mismatch", evidence.SameIDDescriptorMismatch)
	scope.Fact(prefix+"same_descriptor_new_id", evidence.SameDescriptorNewID)
	scope.Fact(prefix+"expected_address_absent", !evidence.SameIDPresent)
	scope.Fact(prefix+"model_absent", evidence.VIDPIDCount == 0)
	scope.Fact(prefix+"vidpid_changed", evidence.VIDPIDChanged)
	scope.Fact(prefix+"usage_changed", evidence.UsageChanged)
	scope.Fact(prefix+"interface_changed", evidence.InterfaceChanged)
	scope.Fact(prefix+"bus_changed", evidence.BusChanged)
}

func sameRecoveryDescriptor(expected, actual Endpoint) bool {
	return expected.VendorID.Known && actual.VendorID.Known && expected.VendorID.Value == actual.VendorID.Value &&
		expected.ProductID.Known && actual.ProductID.Known && expected.ProductID.Value == actual.ProductID.Value &&
		expected.Usage.Known && actual.Usage.Known && expected.Usage.Value == actual.Usage.Value &&
		expected.Bus == actual.Bus && expected.Interface == actual.Interface
}

func observeHotplugReadAdmission(ctx context.Context, conn Conn, done <-chan struct{}) error {
	raw, ok := conn.(*connection)
	if !ok {
		return ErrInvalidArgument
	}
	for {
		raw.mu.Lock()
		admitted := raw.readBusy && !raw.retiring
		raw.mu.Unlock()
		if admitted {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-done:
			return diagnostics.InconclusiveReason("old physical read completed before hotplug admission was observed")
		default:
			runtime.Gosched()
		}
	}
}
