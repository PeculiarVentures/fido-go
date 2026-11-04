//go:build hid_diagnostics

package usb_test

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/PeculiarVentures/fido-go/internal/diagnostics"
)

type usbSleepCallOutcome struct {
	index    int
	response []byte
	err      error
}
type usbSleepCallGroup struct {
	cancel   context.CancelFunc
	ctx      context.Context
	records  []*usbSleepSession
	payloads [][]byte
	outcomes chan usbSleepCallOutcome
	results  []usbSleepCallOutcome
	joined   int
}

func startUSBSleepCalls(ctx context.Context, records []*usbSleepSession) (*usbSleepCallGroup, error) {
	workers, cancel := context.WithCancel(ctx)
	group := &usbSleepCallGroup{ctx: workers, cancel: cancel, records: records, outcomes: make(chan usbSleepCallOutcome, len(records)), results: make([]usbSleepCallOutcome, len(records))}
	for index, record := range records {
		payload, err := usbSleepPayload(1024, index+1)
		if err != nil {
			cancel()
			return nil, err
		}
		if err := record.raw.arm(18); err != nil {
			cancel()
			return nil, err
		}
		group.payloads = append(group.payloads, payload)
	}
	for index, record := range records {
		go func() {
			response, err := record.session.ExchangeHID(workers, 1, group.payloads[index])
			group.outcomes <- usbSleepCallOutcome{index, response, err}
		}()
	}
	return group, nil
}
func (group *usbSleepCallGroup) waitHeld(ctx context.Context, scope *diagnostics.Scope) error {
	bounded, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	for index, record := range group.records {
		if err := record.raw.waitRead(bounded); err != nil {
			return err
		}
		s := record.raw.snapshot()
		if !s.Armed || !s.ReadEntered || !s.ReadActive || s.Released || s.Closed || s.ConfirmedWrites != 18 || s.ForwardedReads != 0 {
			return errors.New("production USB exchange did not enter the intended response barrier after 18 completed reports")
		}
		p := usbSleepKey(index + 1)
		scope.Counter(p+"confirmed_writes_before_prompt", s.ConfirmedWrites)
		scope.Fact(p+"response_read_entered_before_prompt", true)
	}
	scope.Counter("response_barriers_entered", uint64(len(group.records)))
	scope.Fact("all_requests_submitted_before_sleep", true)
	scope.Fact("all_response_reads_held_before_prompt", true)
	return nil
}
func (group *usbSleepCallGroup) finishAfterWake(ctx context.Context, scope *diagnostics.Scope) error {
	responseCtx, cancelResponse := context.WithTimeout(group.ctx, 8*time.Second)
	defer cancelResponse()
	for index, record := range group.records {
		s := record.raw.snapshot()
		scope.Counter(usbSleepKey(index+1)+"forwarded_raw_reads_before_wake", s.ForwardedReads)
		held := s.ReadActive && s.ReadEntered && !s.Released && !s.Closed && s.ConfirmedWrites == 18 && s.ForwardedReads == 0
		scope.Fact(usbSleepKey(index+1)+"response_read_held_until_wake", held)
		if !held {
			return errors.New("production USB caller left its response barrier before matched wake")
		}
	}
	for _, record := range group.records {
		if err := record.raw.release(responseCtx); err != nil {
			return err
		}
	}
	joinCtx, cancelJoin := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelJoin()
	for group.joined < len(group.records) {
		select {
		case result := <-group.outcomes:
			group.results[result.index] = result
			group.joined++
		case <-joinCtx.Done():
			return errors.New("production USB sleep callers did not join after wake")
		}
	}
	scope.Counter("caller_workers_joined", uint64(group.joined))
	scope.Fact("production_callers_joined", true)
	var failures []error
	for index, result := range group.results {
		if err := recordUSBSleepOutcome(scope, group.records[index], group.payloads[index], result.response, result.err, 18); err != nil {
			failures = append(failures, err)
		}
	}
	scope.Fact("all_old_outcomes_recorded", len(failures) == 0)
	return errors.Join(failures...)
}
func (group *usbSleepCallGroup) cleanup(ctx context.Context, scope *diagnostics.Scope) error {
	group.cancel()
	for group.joined < len(group.records) {
		select {
		case result := <-group.outcomes:
			group.results[result.index] = result
			group.joined++
		case <-ctx.Done():
			scope.Fact("production_callers_joined", false)
			return errors.New("production USB sleep callers did not join during cleanup")
		}
	}
	scope.Counter("caller_workers_joined", uint64(group.joined))
	scope.Fact("production_callers_joined", true)
	return nil
}

func recordUSBSleepOutcome(scope *diagnostics.Scope, record *usbSleepSession, payload, response []byte, err error, expected uint64) error {
	p := usbSleepKey(record.ordinal)
	snapshot := record.raw.snapshot()
	scope.Counter(p+"old_expected_writes", expected)
	scope.Counter(p+"old_confirmed_writes", snapshot.ConfirmedWrites)
	exact := err == nil && bytes.Equal(response, payload)
	scope.Fact(p+"old_echo_verified", exact)
	if err == nil && !exact {
		err = errors.New("old production USB sleep exchange returned a different original payload")
	}
	typed := recordUSBSleepOldError(scope, p, err, snapshot.ConfirmedWrites)
	if !typed {
		return errors.New("old production USB exchange failure lacks typed delivery evidence")
	}
	if exact && snapshot.ConfirmedWrites != expected {
		return errors.New("old production USB echo lacks the expected completed write count")
	}
	return nil
}
func probeUSBSleepIdle(ctx context.Context, scope *diagnostics.Scope, records []*usbSleepSession) error {
	var failures []error
	for _, record := range records {
		p := usbSleepKey(record.ordinal)
		scope.Counter(p+"confirmed_writes_before_prompt", 0)
		scope.Counter(p+"forwarded_raw_reads_before_wake", 0)
		scope.Fact(p+"response_read_entered_before_prompt", false)
		scope.Fact(p+"response_read_held_until_wake", false)
		bounded, cancel := context.WithTimeout(ctx, 8*time.Second)
		err := record.raw.arm(1)
		if err == nil {
			err = record.raw.release(bounded)
		}
		payload, payloadErr := usbSleepPayload(24, record.ordinal)
		if payloadErr != nil {
			cancel()
			return payloadErr
		}
		var response []byte
		if err == nil {
			response, err = record.session.ExchangeHID(bounded, 1, payload)
		}
		cancel()
		if evidenceErr := recordUSBSleepOutcome(scope, record, payload, response, err, 1); evidenceErr != nil {
			failures = append(failures, evidenceErr)
		}
	}
	scope.Fact("production_callers_joined", true)
	scope.Fact("all_old_outcomes_recorded", len(failures) == 0)
	return errors.Join(failures...)
}
