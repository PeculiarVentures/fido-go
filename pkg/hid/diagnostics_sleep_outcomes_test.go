//go:build hid_diagnostics && integration && darwin && cgo

package hid

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/PeculiarVentures/fido-go/internal/diagnostics"
	"testing"
	"time"
)

func TestSleepExchangeOutcomesRecordEchoOrExplicitError(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		t.Run(map[bool]string{false: "valid", true: "wrong echo"}[corrupt], func(t *testing.T) {
			outcomes := []diagnosticParallelOutcome{{message: diagnosticMessageResult{Response: []byte{1}, FramesWritten: 18, FramesRead: 18, WriteResult: WriteResult{Outcome: OutcomeCompleted}}}, {message: diagnosticMessageResult{FramesWritten: 18, FramesRead: 0}, err: &Error{Op: "read", Endpoint: "private-selector", Kind: ErrIO, Native: &NativeError{Domain: "iokit", Code: 0xe00002bc}}}}
			if corrupt {
				outcomes[0].message.Response = []byte{9}
			}
			var got error
			report, err := diagnostics.Run(context.Background(), []diagnostics.Scenario{{ID: "outcome", Timeout: time.Second, Run: func(_ context.Context, s *diagnostics.Scope) error {
				got = recordSleepExchangeOutcomes(s, outcomes, [][]byte{{1}, {2}})
				return got
			}}}, diagnostics.Options{})
			if err != nil {
				t.Fatal(err)
			}
			r := report.Results[0]
			if corrupt {
				if got == nil || r.Status != diagnostics.Fail {
					t.Fatalf("wrong echo accepted: %+v", r)
				}
				return
			}
			if got != nil || r.Status != diagnostics.Pass || !r.Facts["key_1_old_echo_verified"] || r.Facts["key_1_old_error_recorded"] || !r.Facts["key_2_old_error_recorded"] || r.Facts["key_2_old_echo_verified"] || r.Counters["key_2_old_error_count"] != 1 || r.Counters["key_2_old_error_categories"] == 0 || r.Counters["key_2_old_native_error_count"] != 1 {
				t.Fatalf("outcome evidence=%+v err=%v", r, got)
			}
			data, encodeErr := json.Marshal(report)
			if encodeErr != nil || bytes.Contains(data, []byte("private-selector")) {
				t.Fatalf("old outcome report leaked selector: %v", encodeErr)
			}
			if len(r.NativeErrors) != 1 || r.NativeErrors[0].Domain != "iokit" || r.NativeErrors[0].Code != 0xe00002bc {
				t.Fatalf("native evidence=%+v", r.NativeErrors)
			}
			if errors.Is(got, ErrIO) {
				t.Fatal("old read error leaked into scenario result despite being recorded")
			}
		})
	}
}

type sleepCloseOnceFailure struct {
	Conn
	calls int
}

func (c *sleepCloseOnceFailure) Close(context.Context) error {
	c.calls++
	if c.calls == 1 {
		return &Error{Op: "close", Endpoint: "private-selector", Kind: ErrIO, Native: &NativeError{Domain: "iokit", Code: 0xe00002bc}}
	}
	return nil
}
func TestSleepCloseRetainsEarlierFailureAfterLaterSuccessfulCleanup(t *testing.T) {
	conn := &sleepCloseOnceFailure{}
	scenario := diagnostics.Scenario{ID: "close-history", Timeout: time.Second, Run: func(ctx context.Context, scope *diagnostics.Scope) error {
		p := &diagnosticSleepClose{scope: scope, prefix: "key_1_"}
		if err := p.close(ctx, conn); err == nil {
			return errors.New("first close error lost")
		}
		if err := p.close(ctx, conn); err != nil {
			return err
		}
		return nil
	}}
	report, err := diagnostics.Run(context.Background(), []diagnostics.Scenario{scenario}, diagnostics.Options{})
	if err != nil || len(report.Results) != 1 {
		t.Fatalf("run=%v", err)
	}
	r := report.Results[0]
	if r.Status != diagnostics.Pass || !r.Facts["key_1_old_close_success"] || !r.Facts["key_1_old_close_error_recorded"] || r.Counters["key_1_old_native_close_errors"] != 1 || len(r.NativeErrors) != 1 || r.NativeErrors[0].Code != 0xe00002bc {
		t.Fatalf("close history=%+v", r)
	}
	data, err := json.Marshal(report)
	if err != nil || bytes.Contains(data, []byte("private-selector")) {
		t.Fatalf("history leaked selector: %v", err)
	}
}
