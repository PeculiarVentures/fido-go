//go:build hid_diagnostics && integration

package hid

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/PeculiarVentures/fido-go/internal/diagnostics"
)

func (collector *identicalCollector) retireRemoved(ctx context.Context, epoch *identicalEpoch, phase int) error {
	epoch.removed = true
	epoch.policy.absenceComplete = true
	// The core input pump already watches removal. This read need not have been
	// admitted before enrollment and is never mislabeled as a blocked-reader test.
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	_, readErr := epoch.conn.Read(bounded, 0)
	cancel()
	if !errors.Is(readErr, ErrRemoved) {
		return errors.Join(diagnostics.InconclusiveReason("removed operator-labelled key did not preserve a native removal error"), readErr)
	}
	epoch.readObserved = true
	epoch.policy.removalObserved = true
	bounded, cancel = context.WithTimeout(context.Background(), 3*time.Second)
	closeErr := epoch.close(bounded)
	cancel()
	if closeErr != nil {
		return closeErr
	}
	bounded, cancel = context.WithTimeout(ctx, 3*time.Second)
	rejectErr := assertSupplementalRetired(bounded, epoch.conn, epoch.cid)
	cancel()
	if rejectErr != nil {
		return rejectErr
	}
	epoch.reuseRejected = true
	if err := collector.staleOpen(ctx, epoch.endpoint, phase); err != nil {
		return err
	}
	epoch.staleRejected = true
	epoch.record()
	return nil
}

func (collector *identicalCollector) staleOpen(ctx context.Context, endpoint Endpoint, phase int) error {
	stats := &collector.phases[phase]
	stats.staleAttempts++
	collector.recordPhase(phase)
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	opened, err := collector.backend.Open(bounded, endpoint)
	cancel()
	if opened != nil {
		collector.scope.Defer(diagnosticClose(collector.scope, opened))
		if opened.Endpoint().ID != endpoint.ID {
			collector.scope.Counter("stale_neighbor_fallback_open_count", 1)
		}
		closeCtx, cancelClose := context.WithTimeout(context.Background(), 3*time.Second)
		closeErr := opened.Close(closeCtx)
		cancelClose()
		return errors.Join(errors.New("exact absent endpoint unexpectedly opened during identical-key qualification"), closeErr)
	}
	if !qualifiesStaleExactOpenRejection(err) {
		return errors.Join(diagnostics.InconclusiveReason("exact absent Open did not establish removed or stale endpoint rejection"), err)
	}
	stats.staleRejections++
	collector.scope.Fact(fmt.Sprintf("phase_%d_stale_removed_or_stale", phase), true)
	collector.recordPhase(phase)
	return nil
}

// All epoch snapshots are copied before their independent probes release. Role
// aggregation runs last in scoped cleanup and never dereferences a released C
// callback/probe context or substitutes a current handle for an old epoch.
func (collector *identicalCollector) recordRoles() {
	for _, role := range []string{"a", "b"} {
		prefix := "role_" + role + "_"
		initialized, closed, removed, qualified, nativeErrors := uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)
		allClosed, allCore, allLeases, allQualified := true, true, true, true
		initialPing := false
		synthetic := false
		for _, epoch := range collector.epochs {
			if epoch.role != role {
				continue
			}
			if epoch.initialized {
				initialized++
			}
			if epoch.closed {
				closed++
			}
			if epoch.removed {
				removed++
			}
			if epoch.qualified {
				qualified++
			}
			if !epoch.closeSuccess {
				nativeErrors++
			}
			allClosed = allClosed && epoch.closed
			allCore = allCore && epoch.coreDone
			allLeases = allLeases && epoch.leaseReleased
			allQualified = allQualified && (epoch.closeSuccess || epoch.qualified)
			synthetic = synthetic || epoch.synthetic
			if epoch.ordinal == 1 {
				initialPing = epoch.pingVerified
			}
		}
		collector.scope.Counter(prefix+"epochs_initialized", initialized)
		collector.scope.Counter(prefix+"epochs_closed", closed)
		collector.scope.Counter(prefix+"removal_events", removed)
		collector.scope.Counter(prefix+"expected_close_diagnostics", qualified)
		collector.scope.Counter(prefix+"native_close_error_count", nativeErrors)
		collector.scope.Fact(prefix+"initial_ping_verified", initialPing)
		collector.scope.Fact(prefix+"synthetic_call", synthetic)
		collector.scope.Fact(prefix+"all_epochs_closed", initialized == 3 && allClosed)
		collector.scope.Fact(prefix+"all_core_cleanup_done", initialized == 3 && allCore)
		collector.scope.Fact(prefix+"all_leases_released", initialized == 3 && allLeases)
		collector.scope.Fact(prefix+"all_expected_close_diagnostics_qualified", initialized == 3 && allQualified)
	}
}
