//go:build hid_diagnostics && integration

package hid

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/PeculiarVentures/fido-go/internal/diagnostics"
)

type identicalPhaseStats struct {
	difference                                       identicalPhaseDifference
	staleAttempts, staleRejections, neighbors, fresh int
	removedMask, addedMask, neighborMask             uint64
	startWrites                                      uint64
}
type identicalCollector struct {
	scope           *diagnostics.Scope
	backend         Backend
	options         hidDiagnosticsOptions
	epochs          []*identicalEpoch
	a, b            *identicalEpoch
	phases          [8]identicalPhaseStats
	confirmedWrites uint64
}

func identicalHardwareDiagnosticRuns(options hidDiagnosticsOptions) []diagnosticRun {
	return []diagnosticRun{{id: "hardware.identical-keys", run: func(ctx context.Context, scope *diagnostics.Scope) error {
		return runIdenticalDiagnostics(ctx, scope, options, New())
	}}}
}

func runIdenticalDiagnostics(ctx context.Context, scope *diagnostics.Scope, options hidDiagnosticsOptions, backend Backend) (runErr error) {
	defer func() { runErr = diagnosticSafeError(scope, runErr) }()
	if !options.InteractiveIdentical {
		return diagnostics.SkipReason("identical-key operator diagnostics were not requested")
	}
	if options.OperatorPrompt == nil {
		return diagnostics.InconclusiveReason("identical-key diagnostics require a bounded operator callback")
	}
	collector := &identicalCollector{scope: scope, backend: backend, options: options}
	scope.Defer(func(context.Context) error { collector.recordRoles(); return nil })
	baseline, pair, err := waitIdenticalInitial(ctx, scope, backend, options.EndpointIDs)
	if err != nil {
		return err
	}
	scope.Counter(diagnosticKeysSelected, 2)
	scope.Counter("initial_endpoint_count", 2)
	scope.Fact("initial_pair_same_descriptor", sameIdenticalDescriptor(pair[0], pair[1]))
	scope.Fact("initial_addresses_distinct", pair[0].ID != pair[1].ID)
	scope.Counter("unlabelled_candidate_count", 2)
	chosen, ambiguity := classifyIdenticalUnlabelled(pair)
	if !errors.Is(ambiguity, errIdenticalAmbiguous) || chosen.ID != "" {
		return errors.New("unlabelled identical-key recovery did not reject two ambiguous candidates")
	}
	scope.Fact("unlabelled_recovery_ambiguous", true)
	for _, counter := range []string{"unlabelled_automatic_open_count", "unexpected_inventory_change_count", "stale_neighbor_fallback_open_count"} {
		scope.Counter(counter, 0)
	}
	for _, fact := range []string{"physical_identity_proven", "physical_port_topology_proven", "serial_identity_asserted", "automatic_ambiguous_recovery", "requests_replayed"} {
		scope.Fact(fact, false)
	}
	scope.Fact("requests_not_replayed", true)
	scope.Fact("operator_requested_port_swap", true)
	initial := make([]*identicalEpoch, 0, 2)
	for index, endpoint := range pair {
		epoch, err := collector.openEpoch(ctx, endpoint, "", index+1)
		if err != nil {
			return err
		}
		initial = append(initial, epoch)
	}
	scope.Counter("initial_report_writes", collector.confirmedWrites)

	// The first observed removal enrolls the operator's A/B labels. Inventory
	// ordering, optional strings and native addresses never assign physical roles.
	difference, err := collector.phase(ctx, baseline, 1, 1, 0, pair[0])
	if err != nil {
		return err
	}
	for _, epoch := range initial {
		if epoch.endpoint.ID == difference.removed[0].ID {
			collector.a = epoch
		} else {
			collector.b = epoch
		}
	}
	if collector.a == nil || collector.b == nil {
		return errors.New("operator role enrollment did not identify one removed and one retained endpoint")
	}
	collector.a.enroll("a", 1)
	collector.b.enroll("b", 1)
	scope.Fact("operator_labels_from_set_difference", true)
	if err := collector.retireRemoved(ctx, collector.a, 1); err != nil {
		return err
	}
	if err := collector.neighbor(ctx, collector.b, difference.snapshot, 1); err != nil {
		return err
	}
	if err := collector.finishPhase(1); err != nil {
		return err
	}
	current := difference.snapshot

	difference, err = collector.phase(ctx, current, 2, 0, 1, pair[0])
	if err != nil {
		return err
	}
	collector.a, err = collector.fresh(ctx, difference.added[0], "a", 2, 2)
	if err != nil {
		return err
	}
	if err := collector.neighbor(ctx, collector.b, difference.snapshot, 2); err != nil {
		return err
	}
	if err := collector.finishPhase(2); err != nil {
		return err
	}
	current = difference.snapshot

	difference, err = collector.phase(ctx, current, 3, 1, 0, pair[0])
	if err != nil {
		return err
	}
	if difference.removed[0].ID != collector.b.endpoint.ID {
		return diagnostics.InconclusiveReason("operator removed the enrolled survivor instead of role B")
	}
	if err := collector.retireRemoved(ctx, collector.b, 3); err != nil {
		return err
	}
	if err := collector.neighbor(ctx, collector.a, difference.snapshot, 3); err != nil {
		return err
	}
	if err := collector.finishPhase(3); err != nil {
		return err
	}
	current = difference.snapshot

	difference, err = collector.phase(ctx, current, 4, 0, 1, pair[0])
	if err != nil {
		return err
	}
	collector.b, err = collector.fresh(ctx, difference.added[0], "b", 2, 4)
	if err != nil {
		return err
	}
	if err := collector.neighbor(ctx, collector.a, difference.snapshot, 4); err != nil {
		return err
	}
	if err := collector.finishPhase(4); err != nil {
		return err
	}
	current = difference.snapshot

	difference, err = collector.phase(ctx, current, 5, 2, 0, pair[0])
	if err != nil {
		return err
	}
	oldA := collector.a.endpoint
	if err := collector.retireRemoved(ctx, collector.a, 5); err != nil {
		return err
	}
	if err := collector.retireRemoved(ctx, collector.b, 5); err != nil {
		return err
	}
	if err := collector.finishPhase(5); err != nil {
		return err
	}
	current = difference.snapshot

	difference, err = collector.phase(ctx, current, 6, 0, 1, pair[0])
	if err != nil {
		return err
	}
	reused := difference.added[0].ID == oldA.ID
	scope.Fact("phase_6_old_a_selector_reused_by_b", reused)
	scope.Fact("phase_6_stale_probe_skipped_for_address_reuse", reused)
	if reused {
		return diagnostics.InconclusiveReason("operator-enrolled B reused the old A address; an address cannot establish physical identity")
	}
	if err := collector.staleOpen(ctx, oldA, 6); err != nil {
		return err
	}
	collector.b, err = collector.fresh(ctx, difference.added[0], "b", 3, 6)
	if err != nil {
		return err
	}
	if err := collector.finishPhase(6); err != nil {
		return err
	}
	current = difference.snapshot

	difference, err = collector.phase(ctx, current, 7, 0, 1, pair[0])
	if err != nil {
		return err
	}
	collector.a, err = collector.fresh(ctx, difference.added[0], "a", 3, 7)
	if err != nil {
		return err
	}
	if err := collector.neighbor(ctx, collector.b, difference.snapshot, 7); err != nil {
		return err
	}
	if err := collector.finishPhase(7); err != nil {
		return err
	}
	for _, epoch := range []*identicalEpoch{collector.a, collector.b} {
		bounded, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		err := epoch.close(bounded)
		cancel()
		if err != nil {
			return err
		}
		rejectCtx, cancelReject := context.WithTimeout(ctx, 3*time.Second)
		rejectErr := assertSupplementalRetired(rejectCtx, epoch.conn, epoch.cid)
		cancelReject()
		if rejectErr != nil {
			return rejectErr
		}
		epoch.reuseRejected = true
		epoch.record()
	}
	scope.Counter(diagnosticKeysCompleted, 2)
	return nil
}

func (collector *identicalCollector) phase(ctx context.Context, before Snapshot, phase, removed, added int, model Endpoint) (identicalPhaseDifference, error) {
	collector.phases[phase].startWrites = collector.confirmedWrites
	difference, err := identicalOperatorPhase(ctx, collector.scope, collector.options, collector.backend, before, phase, removed, added, model)
	collector.phases[phase].difference = difference
	collector.recordPhase(phase)
	return difference, err
}
func (collector *identicalCollector) finishPhase(phase int) error {
	stats := &collector.phases[phase]
	for _, endpoint := range stats.difference.removed {
		mask := collector.roleMask(endpoint.ID)
		if mask == 0 {
			return errors.New("removed address lacks an enrolled operator role")
		}
		stats.removedMask |= mask
	}
	for _, endpoint := range stats.difference.added {
		mask := collector.roleMask(endpoint.ID)
		if mask == 0 {
			return errors.New("added address lacks explicit operator enrollment")
		}
		stats.addedMask |= mask
	}
	collector.recordPhase(phase)
	collector.scope.Counter("phases_completed", uint64(phase))
	return nil
}
func (collector *identicalCollector) roleMask(id EndpointID) uint64 {
	var mask uint64
	if collector.a != nil && collector.a.endpoint.ID == id {
		mask |= 1
	}
	if collector.b != nil && collector.b.endpoint.ID == id {
		mask |= 2
	}
	return mask
}
func (collector *identicalCollector) recordPhase(phase int) {
	s, p := collector.scope, fmt.Sprintf("phase_%d_", phase)
	stats := collector.phases[phase]
	s.Counter(p+"stale_open_attempts", uint64(stats.staleAttempts))
	s.Counter(p+"stale_open_rejections", uint64(stats.staleRejections))
	s.Counter(p+"stale_open_error_count", uint64(stats.staleRejections))
	s.Counter(p+"neighbor_checks", uint64(stats.neighbors))
	s.Counter(p+"fresh_session_count", uint64(stats.fresh))
	s.Counter(p+"fresh_ping_count", uint64(stats.fresh))
	s.Counter(p+"removed_role_mask", stats.removedMask)
	s.Counter(p+"added_role_mask", stats.addedMask)
	s.Counter(p+"neighbor_role_mask", stats.neighborMask)
	s.Counter(p+"confirmed_report_writes", collector.confirmedWrites-stats.startWrites)
}
func (collector *identicalCollector) fresh(ctx context.Context, endpoint Endpoint, role string, ordinal, phase int) (*identicalEpoch, error) {
	epoch, err := collector.openEpoch(ctx, endpoint, role, ordinal)
	if err == nil {
		collector.phases[phase].fresh++
	}
	collector.recordPhase(phase)
	return epoch, err
}
func (collector *identicalCollector) neighbor(ctx context.Context, epoch *identicalEpoch, current Snapshot, phase int) error {
	if _, err := classifyIdenticalSurvivor(current, epoch.endpoint); err != nil {
		return err
	}
	if err := collector.ping(ctx, epoch); err != nil {
		return err
	}
	collector.phases[phase].neighbors++
	collector.phases[phase].neighborMask |= collector.roleMask(epoch.endpoint.ID)
	p := fmt.Sprintf("phase_%d_", phase)
	collector.scope.Fact(p+"neighbor_same_connection", true)
	collector.scope.Fact(p+"neighbor_ping_echo_verified", true)
	collector.recordPhase(phase)
	return nil
}
