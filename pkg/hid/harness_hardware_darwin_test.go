//go:build hid_diagnostics && integration && darwin && cgo

package hid

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/darwin"
	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/diagnostics"
	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/driver"
	wirehid "github.com/PeculiarVentures/fido-go/pkg/wire/hid"
)

func hardwareDiagnosticCapabilities() map[string]bool {
	return map[string]bool{"integration-build": true}
}

func hardwareDiagnosticScenarios(options hidDiagnosticsOptions) []diagnostics.Scenario {
	return []diagnostics.Scenario{
		hardwareSignalScenario("hardware.sigurg-ping", options, false),
		hardwareSignalScenario("hardware.strict-iokit-entry", options, true),
	}
}

func hardwareSignalScenario(id string, options hidDiagnosticsOptions, strict bool) diagnostics.Scenario {
	return diagnostics.Scenario{ID: id, Requirements: []string{"darwin-cgo", "integration-build"}, Timeout: 30 * time.Second, Run: func(ctx context.Context, scope *diagnostics.Scope) error {
		if !options.Hardware {
			return diagnostics.SkipReason("hardware diagnostics not requested")
		}
		if strict && !options.StrictIOKit {
			return diagnostics.SkipReason("strict IOKit-entry diagnostic not requested")
		}
		endpoints, err := diagnosticHardwareEndpoints(ctx, options.EndpointIDs)
		if err != nil {
			return err
		}
		scope.Counter("keys_selected", uint64(len(endpoints)))
		if len(endpoints) == 0 {
			return diagnostics.InconclusiveReason("no selected USB FIDO endpoint is available")
		}
		entryMissing := false
		for index, endpoint := range endpoints {
			confirmed, err := diagnoseHardwarePing(ctx, scope, endpoint, index+1, strict)
			if err != nil {
				return err
			}
			scope.Counter("keys_completed", uint64(index+1))
			if strict && !confirmed {
				entryMissing = true
			}
		}
		scope.Fact("all_ping_echoes_verified", true)
		scope.Fact("all_native_submissions_completed", true)
		scope.Fact("all_masks_restored", true)
		if strict {
			scope.Fact("all_native_entries_confirmed", !entryMissing)
			if entryMissing {
				return diagnostics.InconclusiveReason("strict actual IOKit-entry injection was not confirmed for every selected key")
			}
		} else {
			scope.Fact("all_signals_pending_before_real_call", true)
		}
		return nil
	}}
}

func diagnosticHardwareEndpoints(ctx context.Context, selected []EndpointID) ([]Endpoint, error) {
	bus := BusUSB
	usage := Usage{Page: 0xf1d0, ID: 1}
	snapshot, err := New().Enumerate(ctx, EnumerateOptions{Filter: Filter{Bus: &bus, Usage: &usage}})
	if err != nil {
		return nil, err
	}
	if !snapshot.Complete {
		return nil, diagnostics.InconclusiveReason("USB FIDO inventory is incomplete")
	}
	if len(selected) == 0 {
		return snapshot.Endpoints, nil
	}
	found := make([]Endpoint, 0, len(selected))
	for _, id := range selected {
		matched := false
		for _, endpoint := range snapshot.Endpoints {
			if endpoint.ID == id {
				found = append(found, endpoint)
				matched = true
				break
			}
		}
		if !matched {
			return nil, diagnostics.InconclusiveReason("an explicitly selected USB FIDO endpoint is unavailable")
		}
	}
	return found, nil
}

func diagnoseHardwarePing(ctx context.Context, scope *diagnostics.Scope, endpoint Endpoint, index int, strict bool) (bool, error) {
	bounded, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	conn, err := New().Open(bounded, endpoint)
	if err != nil {
		return false, err
	}
	// Register immediately, including failures before probe attachment/arming.
	scope.Defer(conn.Close)
	layout := conn.Layout()
	if layout.Input.Size != 64 || layout.Output.Size != 64 {
		return false, diagnostics.InconclusiveReason("selected endpoint is outside the qualified 64-byte CTAPHID layout")
	}
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return false, err
	}
	initResponse, _, err := diagnosticHIDMessage(bounded, conn, 0xffffffff, 0x86, nonce)
	if err != nil {
		return false, err
	}
	if len(initResponse) < 17 || !bytes.Equal(initResponse[:8], nonce) {
		return false, errors.New("normal INIT did not return the fresh nonce")
	}
	cid := binary.BigEndian.Uint32(initResponse[8:12])
	if cid == 0 || cid == 0xffffffff {
		return false, errors.New("normal INIT returned an invalid CID")
	}
	var probe *darwin.Probe
	err = withDiagnosticDevice(conn, func(device driver.Device) error {
		var attachErr error
		probe, attachErr = darwin.Attach(device)
		return attachErr
	})
	if err != nil {
		return false, err
	}
	scope.Defer(func(context.Context) error { return probe.Close() })
	// Arm only after INIT: injection must target the intended fresh PING.
	if err := probe.Arm(darwin.Config{InjectSIGURG: !strict, StrictEntry: strict}); err != nil {
		return false, err
	}
	payload := make([]byte, 24)
	if _, err := rand.Read(payload); err != nil {
		return false, err
	}
	response, result, pingErr := diagnosticHIDMessage(bounded, conn, cid, 0x81, payload)
	snapshot := probe.Snapshot()
	recordDarwinDiagnostic(scope, snapshot)
	prefix := fmt.Sprintf("key_%d_", index)
	scope.Counter(prefix+"writer_generation", snapshot.Generation)
	scope.Counter(prefix+"kill_generation", snapshot.KillGeneration)
	scope.Counter(prefix+"entry_generation", snapshot.EntryGeneration)
	scope.Fact(prefix+"native_entry_confirmed", snapshot.EntryConfirmed)
	scope.Fact(prefix+"entry_sigurg_blocked", snapshot.EntrySIGURGBlocked)
	scope.Fact(prefix+"entry_pending_sigurg", snapshot.EntryPendingSIGURG)
	scope.Fact(prefix+"synthetic_call", snapshot.Synthetic)
	scope.Fact(prefix+"mask_restored", snapshot.MaskRestored)
	if pingErr != nil {
		return false, pingErr
	}
	if result.Outcome != OutcomeCompleted || !snapshot.Completed || !snapshot.Submitted || snapshot.SetReportCalls != 1 {
		return false, errors.New("PING did not have exactly one successful native submission")
	}
	if !bytes.Equal(response, payload) {
		return false, errors.New("PING did not return the exact fresh payload")
	}
	if snapshot.Synthetic || !snapshot.MaskRestored || snapshot.MaskQueryError != 0 || snapshot.InitialMaskError != 0 || !snapshot.CriticalSIGURGBlocked {
		return false, errors.New("real PING mask evidence is absent or incorrect")
	}
	scope.Fact(prefix+"ping_echo_verified", true)
	scope.Fact(prefix+"native_submission_completed", true)
	if strict {
		if snapshot.EntryConfirmed {
			if snapshot.EntryGeneration != snapshot.Generation || snapshot.KillGeneration != snapshot.Generation || snapshot.KillAttempts != 1 || snapshot.KillError != 0 || !snapshot.EntrySIGURGBlocked || !snapshot.EntryPendingSIGURG || snapshot.EntryMaskQueryError != 0 {
				return false, errors.New("actual IOKit-entry signal did not target the live protected writer")
			}
		}
	} else {
		if snapshot.EntryConfirmed || snapshot.KillAttempts != 1 || snapshot.KillError != 0 || snapshot.KillGeneration != snapshot.Generation || !snapshot.PendingSIGURG {
			return false, errors.New("pending-before-real-call SIGURG evidence is absent or mislabeled")
		}
		scope.Fact(prefix+"pending_before_real_call", true)
	}
	if err := conn.Close(ctx); err != nil {
		return false, err
	}
	closed := probe.Snapshot()
	if !closed.WriterExited || !closed.WriterJoined || !closed.DeviceClosed {
		return false, errors.New("real diagnostic writer/device cleanup did not complete")
	}
	scope.Fact(prefix+"writer_joined", true)
	return snapshot.EntryConfirmed, nil
}

// diagnosticHIDMessage uses the production wire codec, never an independent
// copy of CTAPHID framing. Each request is submitted once; no replay is allowed.
func diagnosticHIDMessage(ctx context.Context, conn Conn, cid uint32, command byte, payload []byte) ([]byte, WriteResult, error) {
	codec, err := wirehid.NewCodec(cid, command, 64)
	if err != nil {
		return nil, WriteResult{Outcome: OutcomeNotSubmitted}, err
	}
	packets, err := codec.Fragment(payload)
	if err != nil {
		return nil, WriteResult{Outcome: OutcomeNotSubmitted}, err
	}
	result := WriteResult{Outcome: OutcomeNotSubmitted}
	for _, packet := range packets {
		result, err = conn.Write(ctx, Report{ID: conn.Layout().Output.ID, Data: packet})
		if err != nil {
			return nil, result, err
		}
		if result.Outcome != OutcomeCompleted {
			return nil, result, errors.New("diagnostic native write did not confirm completion")
		}
	}
	assembler := codec.NewAssembler()
	for !assembler.Done() {
		report, err := conn.Read(ctx, 0)
		if err != nil {
			return nil, result, err
		}
		if report.ID != conn.Layout().Input.ID || len(report.Data) != 64 {
			return nil, result, errors.New("diagnostic read returned an invalid report format")
		}
		if binary.BigEndian.Uint32(report.Data[:4]) != cid {
			continue
		}
		// Broadcast INIT traffic can include other clients. Ignore a complete
		// single-report INIT response with a different nonce before assembly.
		if command == 0x86 && len(payload) == 8 && report.Data[4] == command && binary.BigEndian.Uint16(report.Data[5:7]) >= 8 && !bytes.Equal(report.Data[7:15], payload) {
			continue
		}
		if err := assembler.Add(report.Data); err != nil {
			return nil, result, err
		}
	}
	response, err := assembler.Payload()
	return response, result, err
}
