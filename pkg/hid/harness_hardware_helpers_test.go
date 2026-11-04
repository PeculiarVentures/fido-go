//go:build hid_diagnostics && integration

package hid

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"

	"github.com/PeculiarVentures/fido-go/internal/diagnostics"
	wirehid "github.com/PeculiarVentures/fido-go/pkg/wire/hid"
)

func diagnosticHardwareEndpoints(ctx context.Context, selected []EndpointID) ([]Endpoint, error) {
	return diagnosticHardwareEndpointsWithBackend(ctx, New(), selected)
}

func diagnosticHardwareEndpointsWithBackend(ctx context.Context, backend Backend, selected []EndpointID) ([]Endpoint, error) {
	selectedSeen := make(map[EndpointID]bool, len(selected))
	for _, id := range selected {
		if selectedSeen[id] {
			return nil, errors.New("duplicate selected HID endpoint")
		}
		selectedSeen[id] = true
	}
	bus := BusUSB
	usage := Usage{Page: 0xf1d0, ID: 1}
	snapshot, err := backend.Enumerate(ctx, EnumerateOptions{Filter: Filter{Bus: &bus, Usage: &usage}})
	if err != nil {
		return nil, err
	}
	if !snapshot.Complete {
		return nil, diagnostics.InconclusiveReason("USB FIDO inventory is incomplete")
	}
	inventorySeen := make(map[EndpointID]bool, len(snapshot.Endpoints))
	for _, endpoint := range snapshot.Endpoints {
		if inventorySeen[endpoint.ID] {
			return nil, errors.New("duplicate HID inventory endpoint")
		}
		inventorySeen[endpoint.ID] = true
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

func openDiagnosticChannel(ctx context.Context, scope *diagnostics.Scope, endpoint Endpoint) (Conn, uint32, error) {
	return openDiagnosticChannelWithBackend(ctx, scope, New(), endpoint)
}

func openDiagnosticChannelWithBackend(ctx context.Context, scope *diagnostics.Scope, backend Backend, endpoint Endpoint) (Conn, uint32, error) {
	return openDiagnosticChannelWithBackendCleanup(ctx, scope, backend, endpoint, nil)
}

func openDiagnosticChannelWithCleanup(ctx context.Context, scope *diagnostics.Scope, endpoint Endpoint, cleanup func(context.Context, Conn) error) (Conn, uint32, error) {
	return openDiagnosticChannelWithBackendCleanup(ctx, scope, New(), endpoint, cleanup)
}

// Custom cleanup is registered immediately after acquisition, before INIT.
// Ordinary callers retain the same default Close behavior.
func openDiagnosticChannelWithBackendCleanup(ctx context.Context, scope *diagnostics.Scope, backend Backend, endpoint Endpoint, cleanup func(context.Context, Conn) error) (Conn, uint32, error) {
	conn, err := backend.Open(ctx, endpoint)
	if err != nil {
		return nil, 0, err
	}
	if cleanup == nil {
		scope.Defer(diagnosticClose(scope, conn))
	} else {
		scope.Defer(func(ctx context.Context) error { return cleanup(ctx, conn) })
	}
	layout := conn.Layout()
	if layout.Input.Size != 64 || layout.Output.Size != 64 {
		return nil, 0, diagnostics.InconclusiveReason("selected endpoint is outside the qualified 64-byte CTAPHID layout")
	}
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return nil, 0, err
	}
	response, _, err := diagnosticHIDMessage(ctx, conn, 0xffffffff, 0x86, nonce)
	if err != nil {
		return nil, 0, err
	}
	if len(response) < 17 || !bytes.Equal(response[:8], nonce) {
		return nil, 0, errors.New("normal INIT did not return the fresh nonce")
	}
	cid := binary.BigEndian.Uint32(response[8:12])
	if cid == 0 || cid == 0xffffffff {
		return nil, 0, errors.New("normal INIT returned an invalid CID")
	}
	return conn, cid, nil
}

type diagnosticMessageResult struct {
	Response                                 []byte
	WriteResult                              WriteResult
	FramesWritten, FramesRead, ForeignFrames int
}

// diagnosticHIDMessage preserves the existing helper boundary for native
// probes. All framing and reassembly come from the production wire codec.
func diagnosticHIDMessage(ctx context.Context, conn Conn, cid uint32, command byte, payload []byte) ([]byte, WriteResult, error) {
	result, err := diagnosticHIDExchange(ctx, conn, cid, command, payload, nil)
	return result.Response, result.WriteResult, err
}

// afterWrite is a test-only barrier after the complete request and before any
// response is consumed. It proves overlapping exchange lifetimes, not parallel
// execution inside native syscalls. Requests are never replayed.
func diagnosticHIDExchange(ctx context.Context, conn Conn, cid uint32, command byte, payload []byte, afterWrite func(context.Context) error) (diagnosticMessageResult, error) {
	result := diagnosticMessageResult{WriteResult: WriteResult{Outcome: OutcomeNotSubmitted}}
	codec, err := wirehid.NewCodec(cid, command, 64)
	if err != nil {
		return result, err
	}
	packets, err := codec.Fragment(payload)
	if err != nil {
		return result, err
	}
	for _, packet := range packets {
		result.WriteResult, err = conn.Write(ctx, Report{ID: conn.Layout().Output.ID, Data: packet})
		if result.WriteResult.Outcome == OutcomeCompleted {
			result.FramesWritten++
		}
		if err != nil {
			return result, err
		}
		if result.WriteResult.Outcome != OutcomeCompleted {
			return result, errors.New("diagnostic native write did not confirm completion")
		}
	}
	if afterWrite != nil {
		if err := afterWrite(ctx); err != nil {
			return result, err
		}
	}
	assembler := codec.NewAssembler()
	for !assembler.Done() {
		report, err := conn.Read(ctx, 0)
		if err != nil {
			return result, err
		}
		if report.ID != conn.Layout().Input.ID || len(report.Data) != 64 {
			return result, errors.New("diagnostic read returned an invalid report format")
		}
		if binary.BigEndian.Uint32(report.Data[:4]) != cid {
			result.ForeignFrames++
			continue
		}
		// INIT broadcast traffic for another fresh nonce is not our response.
		if command == 0x86 && len(payload) == 8 && report.Data[4] == command && binary.BigEndian.Uint16(report.Data[5:7]) >= 8 && !bytes.Equal(report.Data[7:15], payload) {
			result.ForeignFrames++
			continue
		}
		result.FramesRead++
		if err := assembler.Add(report.Data); err != nil {
			return result, err
		}
	}
	result.Response, err = assembler.Payload()
	return result, err
}

func diagnosticPingFrames(size int) int {
	if size <= 57 {
		return 1
	}
	return 1 + (size-57+58)/59
}
