//go:build hid_diagnostics

package usb_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/PeculiarVentures/fido-go/internal/diagnostics"
	"github.com/PeculiarVentures/fido-go/pkg/hid"
	"github.com/PeculiarVentures/fido-go/pkg/transport/usb"
	"testing"
	"time"
)

func TestUSBSleepOldExchangeErrorRecordsDeliveryAndSanitizes(t *testing.T) {
	const secret = "private-usb-selector"
	cause := &hid.Error{Op: "read", Endpoint: secret, Kind: hid.ErrIO, Native: &hid.NativeError{Domain: "iokit", Code: 0xe00002bc, Message: secret}}
	exchange := &usb.ExchangeError{Stage: usb.StageResponse, PacketsSubmitted: 18, Outcome: hid.OutcomeCompleted, Ambiguous: true, Cause: cause}
	scenario := diagnostics.Scenario{ID: "error", Timeout: time.Second, Run: func(_ context.Context, s *diagnostics.Scope) error {
		if !recordUSBSleepOldError(s, "key_1_", exchange, 18) {
			return errors.New("typed exchange rejected")
		}
		return nil
	}}
	r, err := diagnostics.Run(context.Background(), []diagnostics.Scenario{scenario}, diagnostics.Options{})
	if err != nil || len(r.Results) != 1 {
		t.Fatal(err)
	}
	v := r.Results[0]
	if !v.Facts["key_1_old_error_recorded"] || !v.Facts["key_1_old_exchange_error_present"] || !v.Facts["key_1_old_delivery_ambiguous"] || v.Counters["key_1_old_exchange_stage"] != 4 || v.Counters["key_1_old_packets_submitted"] != 18 || v.Counters["key_1_old_write_outcome"] != uint64(hid.OutcomeCompleted) || v.Counters["key_1_old_native_error_count"] != 1 || v.Counters["key_1_old_error_categories"]&(1<<9) == 0 || len(v.NativeErrors) != 1 || v.NativeErrors[0].Code != 0xe00002bc {
		t.Fatalf("evidence=%+v", v)
	}
	raw, err := json.Marshal(r)
	if err != nil || bytes.Contains(raw, []byte(secret)) {
		t.Fatal("report leaked selector")
	}
}
func TestUSBSleepOldUntypedOrUnknownStageErrorIsNotAccepted(t *testing.T) {
	for _, cause := range []error{errors.New("private error"), &usb.ExchangeError{Stage: "other", PacketsSubmitted: 1, Outcome: hid.OutcomeUnknown, Cause: hid.ErrIO}} {
		var accepted bool
		scenario := diagnostics.Scenario{ID: "error", Timeout: time.Second, Run: func(_ context.Context, s *diagnostics.Scope) error {
			accepted = recordUSBSleepOldError(s, "key_1_", cause, 1)
			return nil
		}}
		_, err := diagnostics.Run(context.Background(), []diagnostics.Scenario{scenario}, diagnostics.Options{})
		if err != nil || accepted {
			t.Fatalf("unqualified error accepted: %v", err)
		}
	}
}

type usbSleepCloseSequence struct {
	calls int
	first error
}

func (c *usbSleepCloseSequence) CloseContext(context.Context) error {
	c.calls++
	if c.calls == 1 {
		return c.first
	}
	return nil
}
func TestUSBSleepExplicitCloseFailureRemainsStickyAfterLaterSuccess(t *testing.T) {
	const secret = "private-close-selector"
	closer := &usbSleepCloseSequence{first: &hid.Error{Op: "close", Endpoint: secret, Kind: hid.ErrIO, Native: &hid.NativeError{Domain: "iokit", Code: 0xe00002bc, Message: secret}}}
	scenario := diagnostics.Scenario{ID: "close-history", Timeout: time.Second, Run: func(ctx context.Context, s *diagnostics.Scope) error {
		record := &usbSleepSession{scope: s, ordinal: 1, closer: closer}
		first := record.close(ctx)
		second := record.close(ctx)
		if first == nil || second == nil || !errors.Is(first, hid.ErrIO) || !errors.Is(second, hid.ErrIO) {
			return errors.New("close failure was not sticky")
		}
		return nil
	}}
	report, err := diagnostics.Run(context.Background(), []diagnostics.Scenario{scenario}, diagnostics.Options{})
	if err != nil || len(report.Results) != 1 {
		t.Fatal(err)
	}
	r := report.Results[0]
	if r.Status != diagnostics.Pass || !r.Facts["key_1_old_close_error_recorded"] || r.Facts["key_1_old_close_success"] || r.Counters["key_1_old_close_errors"] != 1 || closer.calls != 2 {
		t.Fatalf("close evidence=%+v calls=%d", r, closer.calls)
	}
	raw, err := json.Marshal(report)
	if err != nil || bytes.Contains(raw, []byte(secret)) {
		t.Fatal("close report leaked selector")
	}
}
