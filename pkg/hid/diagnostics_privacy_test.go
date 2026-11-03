//go:build hid_diagnostics

package hid

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/diagnostics"
)

type privacyCloseConn struct {
	Conn
	err error
}

func (c privacyCloseConn) Close(context.Context) error { return c.err }
func TestDiagnosticsErrorAndCleanupDoNotLeakEndpoint(t *testing.T) {
	const secret = "private-endpoint-selector-12345"
	source := &Error{Op: "read", Endpoint: EndpointID(secret), Kind: ErrIO, Native: &NativeError{Domain: "iokit", Code: 123, Message: secret}, Cause: context.DeadlineExceeded}
	var preserved bool
	scenario := diagnostics.Scenario{ID: "privacy", Timeout: time.Second, Run: func(_ context.Context, scope *diagnostics.Scope) error {
		scope.Defer(diagnosticClose(scope, privacyCloseConn{err: source}))
		safe := diagnosticSafeError(scope, source)
		var native *NativeError
		preserved = errors.Is(safe, ErrIO) && errors.Is(safe, context.DeadlineExceeded) && errors.As(safe, &native) && native.Domain == "iokit" && native.Code == 123
		return safe
	}}
	report, err := diagnostics.Run(context.Background(), []diagnostics.Scenario{scenario}, diagnostics.Options{})
	if err != nil || len(report.Results) != 1 || !preserved {
		t.Fatalf("run=%v preserved=%v", err, preserved)
	}
	r := report.Results[0]
	if r.Status != diagnostics.Fail || r.Cleanup.Complete || len(r.Cleanup.Errors) == 0 || len(r.NativeErrors) == 0 {
		t.Fatalf("result=%+v", r)
	}
	var b bytes.Buffer
	if err := diagnostics.WriteJSON(&b, report); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b.Bytes(), []byte(secret)) {
		t.Fatal("serialized scenario or cleanup leaked endpoint/native message")
	}
}
func TestDiagnosticsSafeErrorPreservesDispositions(t *testing.T) {
	for _, tc := range []struct {
		name  string
		cause error
		want  diagnostics.Status
	}{{"skip", diagnostics.SkipReason("unavailable"), diagnostics.Skip}, {"inconclusive", diagnostics.InconclusiveReason("missing"), diagnostics.Inconclusive}} {
		t.Run(tc.name, func(t *testing.T) {
			errWithID := errors.Join(tc.cause, &Error{Endpoint: "private-id", Kind: ErrRemoved})
			scenario := diagnostics.Scenario{ID: tc.name, Timeout: time.Second, Run: func(_ context.Context, s *diagnostics.Scope) error { return diagnosticSafeError(s, errWithID) }}
			report, err := diagnostics.Run(context.Background(), []diagnostics.Scenario{scenario}, diagnostics.Options{})
			if err != nil || len(report.Results) != 1 || report.Results[0].Status != tc.want {
				t.Fatalf("report=%+v err=%v", report, err)
			}
			var b bytes.Buffer
			if err := diagnostics.WriteJSON(&b, report); err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(b.Bytes(), []byte("private-id")) {
				t.Fatal("disposition report leaked ID")
			}
		})
	}
}
