//go:build hid_diagnostics && integration && darwin && cgo

package hid

import (
	"context"
	"errors"
	"time"

	"github.com/PeculiarVentures/fido-go/internal/diagnostics"
	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/darwin"
)

func hardwareMaskFailureRun(id string, options hidDiagnosticsOptions, restore bool) diagnosticRun {
	return diagnosticRun{id: id, run: func(ctx context.Context, scope *diagnostics.Scope) error {
		endpoints, err := diagnosticHardwareEndpoints(ctx, options.EndpointIDs)
		if err != nil {
			return err
		}
		scope.Counter(diagnosticKeysSelected, uint64(len(endpoints)))
		if len(endpoints) == 0 {
			return diagnostics.InconclusiveReason("no selected USB FIDO endpoint is available")
		}
		for index, endpoint := range endpoints {
			bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
			err := diagnoseHardwareMaskFailure(bounded, scope, endpoint, uint64(index+1), restore)
			cancel()
			if err != nil {
				return err
			}
			scope.Counter(diagnosticKeysCompleted, uint64(index+1))
		}
		for _, fact := range []string{"all_faults_reported", "all_retired_connections_rejected", "all_teardowns_completed", "all_fresh_session_ping_echoes_verified", "requests_not_replayed"} {
			scope.Fact(fact, true)
		}
		return nil
	}}
}

func diagnoseHardwareMaskFailure(ctx context.Context, scope *diagnostics.Scope, endpoint Endpoint, ordinal uint64, restore bool) error {
	prefix := diagnosticKeyPrefix(ordinal)
	conn, cid, err := openDiagnosticChannel(ctx, scope, endpoint)
	if err != nil {
		return err
	}
	scope.Fact(prefix+"fresh_channel_initialized", true)
	probe, err := attachSupplementalProbe(scope, conn)
	if err != nil {
		return err
	}
	config := darwin.Config{BlockUnrelatedSignal: true}
	if restore {
		config.RestoreError = diagnosticMaskFaultCode
	} else {
		config.SetupError = diagnosticMaskFaultCode
	}
	// INIT is complete before arming. The sole affected request is this fresh,
	// read-only PING. A failed-session response is deliberately not consumed.
	if err = probe.Arm(config); err != nil {
		return err
	}
	scope.Fact(prefix+"fault_armed_after_init", true)
	report, err := supplementalPingReport(conn, cid)
	if err != nil {
		return err
	}
	result, writeErr := conn.Write(ctx, report)
	snapshot := probe.Snapshot()
	recordHardwareMaskSnapshot(scope, prefix, snapshot, result)
	scope.Fact(prefix+"failed_session_ping_echo_verified", false)
	if writeErr == nil || !diagnosticErrorCode(writeErr, "pthread", diagnosticMaskFaultCode) {
		return errors.New("physical mask fault did not preserve its configured pthread error")
	}
	// Consume only this expected error, retaining sanitized native-code evidence.
	_ = diagnosticSafeError(scope, writeErr)
	scope.Counter(prefix+"fault_error_code", diagnosticMaskFaultCode)
	scope.Fact(prefix+"fault_error_retained", true)
	if snapshot.Synthetic || snapshot.Generation == 0 || snapshot.Writes != 1 ||
		snapshot.InitialMaskError != 0 || snapshot.MaskQueryError != 0 || snapshot.NativeError != 0 ||
		snapshot.BeforeSIGURGBlocked || !snapshot.BeforeUnrelatedBlocked || !snapshot.AfterUnrelatedBlocked {
		return errors.New("physical mask-fault baseline or native evidence is invalid")
	}
	if restore {
		if snapshot.SetReportCalls != 1 || snapshot.SetupError != 0 || snapshot.RestoreError != diagnosticMaskFaultCode ||
			!snapshot.Submitted || !snapshot.Completed || result.Outcome != OutcomeCompleted ||
			!snapshot.CriticalSIGURGBlocked || !snapshot.AfterSIGURGBlocked || snapshot.MaskRestored {
			return errors.New("physical restore fault lost delivery completion or retained-mask evidence")
		}
		scope.Fact(prefix+"completed_outcome_preserved", true)
		scope.Fact(prefix+"protected_mask_retained_after_restore_failure", true)
	} else {
		if snapshot.SetReportCalls != 0 || snapshot.SetupError != diagnosticMaskFaultCode || snapshot.RestoreError != 0 ||
			snapshot.Submitted || snapshot.Completed || result.Outcome != OutcomeNotSubmitted ||
			snapshot.AfterSIGURGBlocked || !snapshot.MaskRestored {
			return errors.New("physical setup fault submitted a request or altered the original mask")
		}
		scope.Fact(prefix+"setup_failed_not_submitted", true)
		scope.Fact(prefix+"original_mask_intact", true)
	}
	if err = assertSupplementalRetired(ctx, conn, cid); err != nil {
		return err
	}
	scope.Fact(prefix+"old_connection_rejected", true)
	if err = finishSupplementalClose(ctx, conn, probe); err != nil {
		return err
	}
	closed := probe.Snapshot()
	if closed.Generation != snapshot.Generation || closed.Writes != snapshot.Writes || closed.SetReportCalls != snapshot.SetReportCalls {
		return errors.New("faulted writer generation received additional submissions")
	}
	scope.Fact(prefix+"old_generation_no_more_submissions", true)
	scope.Fact(prefix+"writer_exited", closed.WriterExited)
	scope.Fact(prefix+"writer_joined", closed.WriterJoined)
	scope.Fact(prefix+"device_closed", closed.DeviceClosed)
	raw := conn.(*connection)
	select {
	case <-raw.done:
		scope.Fact(prefix+"core_cleanup_done", true)
	default:
		return errors.New("faulted physical connection cleanup has not completed")
	}
	shared.mu.Lock()
	leaseHeld := shared.endpoints[raw.lease]
	shared.mu.Unlock()
	if leaseHeld {
		return errors.New("faulted physical endpoint lease was not released")
	}
	scope.Fact(prefix+"endpoint_lease_released", true)
	return diagnoseFreshHardwareMaskSession(ctx, scope, endpoint, prefix, snapshot.Generation)
}

func diagnoseFreshHardwareMaskSession(ctx context.Context, scope *diagnostics.Scope, endpoint Endpoint, prefix string, oldGeneration uint64) error {
	fresh, cid, err := openDiagnosticChannel(ctx, scope, endpoint)
	if err != nil {
		return err
	}
	scope.Fact(prefix+"fresh_session_initialized", true)
	probe, err := attachSupplementalProbe(scope, fresh)
	if err != nil {
		return err
	}
	if err = probe.Arm(darwin.Config{BlockUnrelatedSignal: true}); err != nil {
		return err
	}
	if err = supplementalFreshPing(ctx, fresh, cid); err != nil {
		return err
	}
	snapshot := probe.Snapshot()
	scope.Counter(prefix+"fresh_writer_generation", snapshot.Generation)
	scope.Counter(prefix+"fresh_set_report_calls", snapshot.SetReportCalls)
	scope.Fact(prefix+"fresh_synthetic_call", snapshot.Synthetic)
	if snapshot.Synthetic || snapshot.Generation <= oldGeneration || snapshot.SetReportCalls != 1 ||
		!snapshot.Submitted || !snapshot.Completed || !snapshot.MaskRestored ||
		snapshot.InitialMaskError != 0 || snapshot.MaskQueryError != 0 || snapshot.NativeError != 0 ||
		snapshot.SetupError != 0 || snapshot.RestoreError != 0 {
		return errors.New("fresh physical session lacks independent successful native evidence")
	}
	scope.Fact(prefix+"no_generation_reuse", true)
	scope.Fact(prefix+"fresh_session_ping_echo_verified", true)
	scope.Fact(prefix+"fresh_native_completed", true)
	scope.Fact(prefix+"fresh_mask_restored", true)
	if err = finishSupplementalClose(ctx, fresh, probe); err != nil {
		return err
	}
	closed := probe.Snapshot()
	scope.Fact(prefix+"fresh_writer_joined", closed.WriterJoined)
	scope.Fact(prefix+"fresh_device_closed", closed.DeviceClosed)
	scope.Fact(prefix+"requests_not_replayed", true)
	return nil
}

func recordHardwareMaskSnapshot(scope *diagnostics.Scope, prefix string, snapshot darwin.Snapshot, result WriteResult) {
	for name, count := range map[string]uint64{
		diagnosticWriterGeneration: snapshot.Generation, "set_report_calls": snapshot.SetReportCalls, "writes": snapshot.Writes,
		"write_outcome": uint64(result.Outcome), "setup_error": uint64(snapshot.SetupError), "restore_error": uint64(snapshot.RestoreError),
		"native_result_code": uint64(snapshot.NativeError), "initial_mask_error": uint64(snapshot.InitialMaskError), "mask_query_error": uint64(snapshot.MaskQueryError),
	} {
		scope.Counter(prefix+name, count)
	}
	for name, observed := range map[string]bool{
		"synthetic_call": snapshot.Synthetic, "before_sigurg_blocked": snapshot.BeforeSIGURGBlocked,
		"before_unrelated_blocked": snapshot.BeforeUnrelatedBlocked, "critical_sigurg_blocked": snapshot.CriticalSIGURGBlocked,
		"after_sigurg_blocked": snapshot.AfterSIGURGBlocked, "after_unrelated_blocked": snapshot.AfterUnrelatedBlocked,
		"mask_restored": snapshot.MaskRestored, "submitted": snapshot.Submitted, "completed": snapshot.Completed,
	} {
		scope.Fact(prefix+name, observed)
	}
}
