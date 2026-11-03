//go:build hid_diagnostics && integration

package hid

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/diagnostics"
)

func portableHardwareDiagnosticScenarios(options hidDiagnosticsOptions) []diagnostics.Scenario {
	return []diagnostics.Scenario{
		{ID: "hardware.multiframe-ping", Requirements: []string{"integration-build"}, Timeout: 40 * time.Second, Run: func(ctx context.Context, scope *diagnostics.Scope) error {
			if !options.Hardware {
				return diagnostics.SkipReason("hardware diagnostics not requested")
			}
			return runDiagnosticMultiframe(ctx, scope, New(), options.EndpointIDs)
		}},
		{ID: "hardware.parallel-exchange", Requirements: []string{"integration-build"}, Timeout: 30 * time.Second, Run: func(ctx context.Context, scope *diagnostics.Scope) error {
			if !options.Hardware {
				return diagnostics.SkipReason("hardware diagnostics not requested")
			}
			return runDiagnosticParallel(ctx, scope, New(), options.EndpointIDs)
		}},
	}
}

func runDiagnosticMultiframe(ctx context.Context, scope *diagnostics.Scope, backend Backend, selected []EndpointID) (resultErr error) {
	defer func() { resultErr = diagnosticSafeError(scope, resultErr) }()
	endpoints, err := diagnosticHardwareEndpointsWithBackend(ctx, backend, selected)
	if err != nil {
		return err
	}
	scope.Counter("keys_selected", uint64(len(endpoints)))
	if len(endpoints) == 0 {
		return diagnostics.InconclusiveReason("no selected USB FIDO endpoint is available")
	}
	sizes := []int{0, 57, 58, 128, 1024}
	scope.Counter("payload_cases_per_key", uint64(len(sizes)))
	for index, endpoint := range endpoints {
		bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
		conn, cid, err := openDiagnosticChannelWithBackend(bounded, scope, backend, endpoint)
		if err != nil {
			cancel()
			return err
		}
		prefix := fmt.Sprintf("key_%d_", index+1)
		scope.Fact(prefix+"fresh_channel_initialized", true)
		for completed, size := range sizes {
			payload := make([]byte, size)
			if _, err := rand.Read(payload); err != nil {
				cancel()
				return err
			}
			result, err := diagnosticHIDExchange(bounded, conn, cid, 0x81, payload, nil)
			casePrefix := fmt.Sprintf("%spayload_%d_", prefix, size)
			scope.Counter(casePrefix+"frames_written", uint64(result.FramesWritten))
			scope.Counter(casePrefix+"frames_read", uint64(result.FramesRead))
			scope.Counter(casePrefix+"foreign_frames", uint64(result.ForeignFrames))
			scope.Counter(casePrefix+"frames_expected", uint64(diagnosticPingFrames(size)))
			if err != nil {
				cancel()
				return err
			}
			if !bytes.Equal(result.Response, payload) {
				cancel()
				return errors.New("multiframe PING did not echo its exact fresh payload")
			}
			if result.FramesWritten != diagnosticPingFrames(size) || result.FramesRead != diagnosticPingFrames(size) {
				cancel()
				return errors.New("multiframe PING frame counts did not match the production codec layout")
			}
			scope.Fact(casePrefix+"echo_verified", true)
			scope.Fact(casePrefix+"native_writes_completed", result.WriteResult.Outcome == OutcomeCompleted)
			scope.Counter(prefix+"payload_cases_completed", uint64(completed+1))
		}
		if err := conn.Close(bounded); err != nil {
			cancel()
			return err
		}
		cancel()
		scope.Fact(prefix+"closed", true)
		scope.Counter("keys_completed", uint64(index+1))
	}
	scope.Fact("all_payload_echoes_verified", true)
	scope.Fact("all_frame_counts_verified", true)
	scope.Fact("requests_not_replayed", true)
	return nil
}
