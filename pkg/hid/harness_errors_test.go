//go:build hid_diagnostics

package hid

import (
	"context"
	"errors"

	"github.com/PeculiarVentures/fido-go/internal/diagnostics"
	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/driver"
)

// Diagnostic output keeps typed categories and native codes, but never formats
// hid.Error: that public type intentionally includes the selected EndpointID.
func diagnosticSafeError(scope *diagnostics.Scope, err error) error {
	if err == nil {
		return nil
	}
	var endpointError *Error
	if !errors.As(err, &endpointError) {
		return err
	}
	safe := []error{errors.New("HID diagnostic native operation failed")}
	for _, kind := range []error{ErrClosed, ErrRemoved, ErrPermission, ErrBusy, ErrUnsupported, ErrInvalidArgument, ErrInvalidReport, ErrStaleEndpoint, ErrTimeout, ErrIO, ErrResourceLimit, context.Canceled, context.DeadlineExceeded} {
		if errors.Is(err, kind) {
			safe = append(safe, kind)
		}
	}
	type nativeCode struct {
		domain string
		code   uint64
	}
	seen := make(map[nativeCode]bool)
	var walk func(error)
	walk = func(cause error) {
		if cause == nil {
			return
		}
		var code nativeCode
		switch value := cause.(type) {
		case *NativeError:
			code = nativeCode{value.Domain, value.Code}
		case *driver.Error:
			code = nativeCode{value.Domain, value.Code}
		}
		if code.domain != "" && !seen[code] {
			seen[code] = true
			safe = append(safe, &NativeError{Domain: code.domain, Code: code.code})
			if scope != nil {
				scope.Native(diagnostics.NativeError{Operation: "HID operation", Domain: code.domain, Code: code.code})
			}
		}
		if many, ok := cause.(interface{ Unwrap() []error }); ok {
			for _, child := range many.Unwrap() {
				walk(child)
			}
		}
		if one, ok := cause.(interface{ Unwrap() error }); ok {
			walk(one.Unwrap())
		}
	}
	walk(err)
	if status, ok := diagnostics.Disposition(err); ok {
		switch status {
		case diagnostics.Skip:
			safe = append(safe, diagnostics.SkipReason("HID diagnostic prerequisite unavailable"))
		case diagnostics.Inconclusive:
			safe = append(safe, diagnostics.InconclusiveReason("HID diagnostic evidence is incomplete"))
		}
	}
	return errors.Join(safe...)
}

func diagnosticClose(scope *diagnostics.Scope, conn Conn) func(context.Context) error {
	return func(ctx context.Context) error { return diagnosticSafeError(scope, conn.Close(ctx)) }
}
