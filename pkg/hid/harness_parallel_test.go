//go:build hid_diagnostics && integration

package hid

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"time"

	"github.com/PeculiarVentures/fido-go/internal/diagnostics"
)

type diagnosticParallelKey struct {
	conn    Conn
	cid     uint32
	payload []byte
}
type diagnosticParallelOutcome struct {
	index   int
	message diagnosticMessageResult
	err     error
}

// runDiagnosticParallel holds complete requests at a response barrier while
// inventory is polled. The evidence concerns outstanding logical exchanges;
// no start flag or timestamp is used to infer simultaneous native syscalls.
func runDiagnosticParallel(ctx context.Context, scope *diagnostics.Scope, backend Backend, selected []EndpointID) (resultErr error) {
	defer func() { resultErr = diagnosticSafeError(scope, resultErr) }()
	endpoints, err := diagnosticHardwareEndpointsWithBackend(ctx, backend, selected)
	if err != nil {
		return err
	}
	scope.Counter(diagnosticKeysSelected, uint64(len(endpoints)))
	if len(endpoints) < 2 {
		return diagnostics.InconclusiveReason("parallel exchange requires at least two independent selected endpoints")
	}
	seen := make(map[EndpointID]bool)
	for _, endpoint := range endpoints {
		if seen[endpoint.ID] {
			return errors.New("parallel exchange selected a duplicate endpoint address")
		}
		seen[endpoint.ID] = true
	}
	bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	keys := make([]diagnosticParallelKey, 0, len(endpoints))
	for index, endpoint := range endpoints {
		conn, cid, err := openDiagnosticChannelWithBackend(bounded, scope, backend, endpoint)
		if err != nil {
			return err
		}
		payload := make([]byte, 1024)
		if _, err := rand.Read(payload); err != nil {
			return err
		}
		// Ensure neighboring keys' payloads differ even independently of RNG output.
		binary.BigEndian.PutUint32(payload[:4], uint32(index+1))
		keys = append(keys, diagnosticParallelKey{conn: conn, cid: cid, payload: payload})
	}
	scope.Fact("independent_endpoint_addresses", true)
	start := make(chan struct{})
	releaseResponses := make(chan struct{})
	started := make(chan struct{}, len(keys))
	requestReady := make(chan int, len(keys))
	outcomes := make(chan diagnosticParallelOutcome, len(keys))
	joined := 0
	// Every error path releases barriers and joins caller workers within an
	// independent budget. Native ownership remains with each Conn supervisor.
	defer func() {
		cancel()
		closeDiagnosticGate(start)
		closeDiagnosticGate(releaseResponses)
		cleanup, cancelCleanup := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancelCleanup()
		for joined < len(keys) {
			select {
			case <-outcomes:
				joined++
			case <-cleanup.Done():
				scope.Fact("parallel_workers_joined", false)
				resultErr = errors.Join(resultErr, errors.New("parallel diagnostic workers did not join within cleanup budget"))
				return
			}
		}
		scope.Fact("parallel_workers_joined", true)
	}()
	for index, key := range keys {
		go func() {
			started <- struct{}{}
			select {
			case <-start:
			case <-bounded.Done():
				outcomes <- diagnosticParallelOutcome{index: index, err: bounded.Err()}
				return
			}
			message, err := diagnosticHIDExchange(bounded, key.conn, key.cid, 0x81, key.payload, func(wait context.Context) error {
				requestReady <- index
				select {
				case <-releaseResponses:
					return nil
				case <-wait.Done():
					return wait.Err()
				}
			})
			outcomes <- diagnosticParallelOutcome{index: index, message: message, err: err}
		}()
	}
	for range keys {
		select {
		case <-started:
		case <-bounded.Done():
			return bounded.Err()
		}
	}
	scope.Fact("workers_ready_before_start", true)
	close(start)
	ready := make(map[int]bool, len(keys))
	for len(ready) < len(keys) {
		select {
		case index := <-requestReady:
			ready[index] = true
		case outcome := <-outcomes:
			joined++
			if outcome.err != nil {
				return outcome.err
			}
			return errors.New("parallel worker completed before response barrier was released")
		case <-bounded.Done():
			return bounded.Err()
		}
	}
	scope.Counter("max_overlapping_exchanges", uint64(len(ready)))
	scope.Fact("all_requests_submitted_at_response_barrier", true)
	// Two finished inventory observations while every exchange remains held at
	// its response barrier establish polling during the proven overlap interval.
	for poll := 1; poll <= 2; poll++ {
		observed, err := diagnosticHardwareEndpointsWithBackend(bounded, backend, nil)
		if err != nil {
			return err
		}
		present := make(map[EndpointID]bool, len(observed))
		for _, endpoint := range observed {
			present[endpoint.ID] = true
		}
		for _, endpoint := range endpoints {
			if !present[endpoint.ID] {
				return diagnostics.InconclusiveReason("selected endpoint disappeared from complete concurrent inventory")
			}
		}
		scope.Counter("inventory_polls_completed", uint64(poll))
	}
	scope.Fact("complete_inventory_during_overlap", true)
	close(releaseResponses)
	for joined < len(keys) {
		select {
		case outcome := <-outcomes:
			joined++
			prefix := diagnosticKeyPrefix(uint64(outcome.index + 1))
			scope.Counter(prefix+"frames_written", uint64(outcome.message.FramesWritten))
			scope.Counter(prefix+"frames_read", uint64(outcome.message.FramesRead))
			scope.Counter(prefix+"frames_expected", uint64(diagnosticPingFrames(1024)))
			scope.Counter(prefix+"foreign_frames", uint64(outcome.message.ForeignFrames))
			if outcome.err != nil {
				return outcome.err
			}
			if !bytes.Equal(outcome.message.Response, keys[outcome.index].payload) {
				return errors.New("parallel PING response crossed an endpoint or payload boundary")
			}
			if outcome.message.FramesWritten != diagnosticPingFrames(1024) || outcome.message.FramesRead != diagnosticPingFrames(1024) {
				return errors.New("parallel PING frame count was incomplete")
			}
			scope.Fact(prefix+"response_isolated", true)
			scope.Fact(prefix+"echo_verified", true)
			scope.Counter(diagnosticKeysCompleted, uint64(joined))
		case <-bounded.Done():
			return bounded.Err()
		}
	}
	scope.Fact("all_payload_echoes_verified", true)
	scope.Fact("all_responses_isolated", true)
	scope.Fact("requests_not_replayed", true)
	return nil
}
