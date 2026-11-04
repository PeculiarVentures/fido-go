//go:build hid_diagnostics && integration && darwin && cgo

package hid

import (
	"context"
	"errors"
	"time"

	"github.com/PeculiarVentures/fido-go/internal/diagnostics"
)

type diagnosticSleepSession struct {
	endpoint Endpoint
	conn     Conn
	cid      uint32
	close    *diagnosticSleepClose
}

type diagnosticSleepClose struct {
	scope         *diagnostics.Scope
	prefix        string
	probe         hotplugCloseProbe
	closeFailures uint64
}

func (policy *diagnosticSleepClose) close(ctx context.Context, conn Conn) error {
	err := conn.Close(ctx)
	coreDone, leaseReleased := false, false
	if raw, ok := conn.(*connection); ok {
		select {
		case <-raw.done:
			coreDone = true
		default:
		}
		shared.mu.Lock()
		leaseReleased = !shared.endpoints[raw.lease]
		shared.mu.Unlock()
	}
	proof := hotplugCloseProof{}
	if policy.probe != nil {
		proof = policy.probe.proof()
	}
	p := policy.prefix
	policy.scope.Fact(p+"old_close_success", err == nil)
	if err != nil {
		policy.closeFailures++
	}
	policy.scope.Fact(p+"old_close_error_recorded", policy.closeFailures > 0)
	policy.scope.Counter(p+"old_native_close_errors", policy.closeFailures)
	policy.scope.Fact(p+"old_core_cleanup_done", coreDone)
	policy.scope.Fact(p+"old_endpoint_lease_released", leaseReleased)
	policy.scope.Fact(p+"old_writer_exited", proof.WriterExited)
	policy.scope.Fact(p+"old_writer_joined", proof.WriterJoined)
	policy.scope.Fact(p+"old_device_closed", proof.DeviceClosed)
	complete := coreDone && leaseReleased && proof.RealProbe && proof.SameProbe && proof.WriterExited && proof.WriterJoined && proof.DeviceClosed
	policy.scope.Fact(p+"old_cleanup_complete", complete)
	// Unlike the physical-unplug policy, sleep never normalizes a native Close
	// error. Keep its codes and fail even if independent teardown proof exists.
	if err != nil {
		return diagnosticSafeError(policy.scope, err)
	}
	if policy.probe != nil && !complete {
		return errors.New("old sleep session lacks completed native teardown evidence")
	}
	return nil
}

func (policy *diagnosticSleepClose) cleanup(ctx context.Context, conn Conn) error {
	err := policy.close(ctx, conn)
	if policy.probe != nil {
		err = errors.Join(err, policy.probe.close())
	}
	return diagnosticSafeError(policy.scope, err)
}

func openSleepSessions(ctx context.Context, scope *diagnostics.Scope, backend Backend, selected []Endpoint, attach func(Conn) (hotplugCloseProbe, error)) ([]diagnosticSleepSession, error) {
	sessions := make([]diagnosticSleepSession, 0, len(selected))
	for index, endpoint := range selected {
		p := diagnosticKeyPrefix(uint64(index + 1))
		policy := &diagnosticSleepClose{scope: scope, prefix: p}
		bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
		conn, cid, err := openDiagnosticChannelWithBackendCleanup(bounded, scope, backend, endpoint, policy.cleanup)
		if err != nil {
			cancel()
			return nil, err
		}
		policy.probe, err = attach(conn)
		if err == nil {
			scope.Fact(p+"initialized_before_sleep", true)
			err = supplementalFreshPing(bounded, conn, cid)
		}
		cancel()
		if err != nil {
			return nil, err
		}
		scope.Fact(p+"warmup_ping_verified", true)
		scope.Fact(p+"physical_identity_proven", false)
		sessions = append(sessions, diagnosticSleepSession{endpoint: endpoint, conn: conn, cid: cid, close: policy})
	}
	scope.Fact("all_keys_initialized_before_sleep", true)
	scope.Fact("all_keys_warmed_before_sleep", true)
	return sessions, nil
}

func closeSleepSessions(scope *diagnostics.Scope, sessions []diagnosticSleepSession) error {
	var failures []error
	all := true
	for _, session := range sessions {
		// A caller deadline does not stop this bounded cleanup attempt or relinquish
		// native ownership. A second scoped cleanup will wait on the same supervisor.
		bounded, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		err := session.close.close(bounded, session.conn)
		cancel()
		if err != nil {
			all = false
			failures = append(failures, err)
		}
	}
	scope.Fact("all_old_sessions_cleanup_complete", all)
	return errors.Join(failures...)
}

func recoverSleepSessions(ctx context.Context, scope *diagnostics.Scope, backend Backend, sessions []diagnosticSleepSession) error {
	expected := make([]Endpoint, len(sessions))
	for index, session := range sessions {
		expected[index] = session.endpoint
		scope.Counter(diagnosticKeyPrefix(uint64(index+1))+"fresh_recovery_attempts", 1)
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	current, err := diagnosticHardwareEndpointsWithBackend(bounded, backend, nil)
	if err != nil {
		return err
	}
	candidates, err := sleepRecoveryCandidates(expected, current)
	if err != nil {
		return err
	}
	var failures []error
	completed := uint64(0)
	for index, endpoint := range candidates {
		p := diagnosticKeyPrefix(uint64(index + 1))
		scope.Fact(p+"fresh_inventory_complete", true)
		scope.Fact(p+"unique_observed_descriptor_recovery", true)
		scope.Fact(p+"fresh_address_changed", endpoint.ID != expected[index].ID)
		scope.Counter(p+"fresh_probe_attempts", 1)
		probeCtx, cancelProbe := context.WithTimeout(bounded, 10*time.Second)
		conn, cid, probeErr := openDiagnosticChannelWithBackend(probeCtx, scope, backend, endpoint)
		if probeErr == nil {
			probeErr = supplementalFreshPing(probeCtx, conn, cid)
		}
		if probeErr == nil {
			scope.Fact(p+"fresh_init_ping_verified", true)
		}
		if conn != nil {
			closeCtx, cancelClose := context.WithTimeout(context.Background(), 3*time.Second)
			closeErr := conn.Close(closeCtx)
			cancelClose()
			scope.Fact(p+"fresh_closed", closeErr == nil)
			probeErr = errors.Join(probeErr, closeErr)
		}
		cancelProbe()
		if probeErr != nil {
			failures = append(failures, probeErr)
		} else {
			completed++
		}
		scope.Counter(diagnosticKeysCompleted, completed)
	}
	scope.Fact("all_fresh_recoveries_ping_verified", completed == uint64(len(sessions)))
	return errors.Join(failures...)
}
