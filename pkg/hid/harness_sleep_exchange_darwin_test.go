//go:build hid_diagnostics && integration && darwin && cgo

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

// responseCtx is published before the release channel closes. Workers cannot
// call Read until that barrier releases, so its deadline starts after wake.
type diagnosticSleepReadConn struct {
	Conn
	responseCtx context.Context
}

func (conn *diagnosticSleepReadConn) Read(ctx context.Context, wait time.Duration) (Report, error) {
	if conn.responseCtx != nil {
		ctx = conn.responseCtx
	}
	return conn.Conn.Read(ctx, wait)
}

type diagnosticSleepExchangeGroup struct {
	ctx      context.Context
	cancel   context.CancelFunc
	release  chan struct{}
	ready    chan int
	outcomes chan diagnosticParallelOutcome
	wrappers []*diagnosticSleepReadConn
	payloads [][]byte
	results  []diagnosticParallelOutcome
	joined   int
}

func startSleepExchanges(ctx context.Context, sessions []diagnosticSleepSession) (*diagnosticSleepExchangeGroup, error) {
	workerCtx, cancel := context.WithCancel(ctx)
	group := &diagnosticSleepExchangeGroup{ctx: workerCtx, cancel: cancel, release: make(chan struct{}), ready: make(chan int, len(sessions)), outcomes: make(chan diagnosticParallelOutcome, len(sessions)), results: make([]diagnosticParallelOutcome, len(sessions))}
	// Allocate all payloads before starting workers; acquisition failures cannot
	// strand a partially launched group without its cleanup owner.
	for index, session := range sessions {
		payload := make([]byte, 1024)
		if _, err := rand.Read(payload); err != nil {
			cancel()
			return nil, err
		}
		binary.BigEndian.PutUint32(payload[:4], uint32(index+1))
		group.payloads = append(group.payloads, payload)
		group.wrappers = append(group.wrappers, &diagnosticSleepReadConn{Conn: session.conn})
	}
	for index, session := range sessions {
		go func() {
			result, err := diagnosticHIDExchange(workerCtx, group.wrappers[index], session.cid, 0x81, group.payloads[index], func(ctx context.Context) error {
				group.ready <- index
				select {
				case <-group.release:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			})
			group.outcomes <- diagnosticParallelOutcome{index: index, message: result, err: err}
		}()
	}
	return group, nil
}

func (group *diagnosticSleepExchangeGroup) waitHeld(ctx context.Context, scope *diagnostics.Scope) error {
	bounded, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	held := make(map[int]bool, len(group.wrappers))
	for len(held) < len(group.wrappers) {
		select {
		case index := <-group.ready:
			held[index] = true
		case outcome := <-group.outcomes:
			group.results[outcome.index] = outcome
			group.joined++
			if outcome.err != nil {
				return outcome.err
			}
			return errors.New("sleep exchange completed before its response barrier")
		case <-bounded.Done():
			return bounded.Err()
		}
	}
	scope.Counter("exchanges_held_before_prompt", uint64(len(held)))
	scope.Fact("all_requests_submitted_before_sleep", true)
	scope.Fact("all_response_workers_held_before_prompt", true)
	return nil
}

func (group *diagnosticSleepExchangeGroup) finishAfterWake(ctx context.Context, scope *diagnostics.Scope) error {
	responseCtx, cancelResponse := context.WithTimeout(ctx, 8*time.Second)
	defer cancelResponse()
	for _, conn := range group.wrappers {
		conn.responseCtx = responseCtx
	}
	closeDiagnosticGate(group.release)
	// Context cancellation is honored by public Conn calls; this separate join
	// budget leaves native ownership with the supervisor if completion is late.
	joinCtx, cancelJoin := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelJoin()
	for group.joined < len(group.wrappers) {
		select {
		case outcome := <-group.outcomes:
			group.results[outcome.index] = outcome
			group.joined++
		case <-joinCtx.Done():
			return errors.New("sleep response workers did not join after wake within the bounded budget")
		}
	}
	scope.Fact("response_workers_joined", true)
	return recordSleepExchangeOutcomes(scope, group.results, group.payloads)
}

func (group *diagnosticSleepExchangeGroup) cleanup(ctx context.Context, scope *diagnostics.Scope) error {
	group.cancel()
	closeDiagnosticGate(group.release)
	for group.joined < len(group.wrappers) {
		select {
		case outcome := <-group.outcomes:
			group.results[outcome.index] = outcome
			group.joined++
		case <-ctx.Done():
			scope.Fact("response_workers_joined", false)
			return errors.New("sleep exchange workers did not join during cleanup")
		}
	}
	scope.Fact("response_workers_joined", true)
	return nil
}

func recordSleepExchangeOutcomes(scope *diagnostics.Scope, outcomes []diagnosticParallelOutcome, payloads [][]byte) error {
	var failures []error
	for index, outcome := range outcomes {
		if outcome.err == nil && !bytes.Equal(outcome.message.Response, payloads[index]) {
			failures = append(failures, errors.New("old sleep exchange returned a different original payload"))
			continue
		}
		if err := recordSleepOldOutcome(scope, index+1, outcome.message, outcome.err, 18); err != nil {
			failures = append(failures, err)
		}
	}
	scope.Fact("all_old_outcomes_recorded", len(failures) == 0)
	return errors.Join(failures...)
}

func recordSleepOldOutcome(scope *diagnostics.Scope, ordinal int, result diagnosticMessageResult, err error, expected int) error {
	p := diagnosticKeyPrefix(uint64(ordinal))
	scope.Counter(p+"old_request_attempts", 1)
	scope.Counter(p+"old_frames_expected", uint64(expected))
	scope.Counter(p+"old_frames_written", uint64(result.FramesWritten))
	scope.Counter(p+"old_frames_read", uint64(result.FramesRead))
	scope.Fact(p+"old_echo_verified", err == nil)
	recordSleepOldError(scope, p, err)
	scope.Fact(p+"old_outcome_recorded", true)
	if err == nil && (result.FramesWritten != expected || result.FramesRead != expected || result.WriteResult.Outcome != OutcomeCompleted) {
		return errors.New("old sleep-session echo lacks complete native report evidence")
	}
	return nil
}

func probeIdleSleepSessions(ctx context.Context, scope *diagnostics.Scope, sessions []diagnosticSleepSession) error {
	var failures []error
	for index, session := range sessions {
		bounded, cancel := context.WithTimeout(ctx, 8*time.Second)
		payload := make([]byte, 24)
		if _, err := rand.Read(payload); err != nil {
			cancel()
			return err
		}
		result, err := diagnosticHIDExchange(bounded, session.conn, session.cid, 0x81, payload, nil)
		cancel()
		if err == nil && !bytes.Equal(result.Response, payload) {
			failures = append(failures, errors.New("old idle sleep session returned a different fresh payload"))
			continue
		}
		if evidenceErr := recordSleepOldOutcome(scope, index+1, result, err, 1); evidenceErr != nil {
			failures = append(failures, evidenceErr)
		}
	}
	scope.Fact("all_old_outcomes_recorded", len(failures) == 0)
	return errors.Join(failures...)
}
