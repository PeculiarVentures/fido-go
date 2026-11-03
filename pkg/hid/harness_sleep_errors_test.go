//go:build hid_diagnostics

package hid

import (
	"context"
	"errors"

	"github.com/PeculiarVentures/fido-go/internal/diagnostics"
	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/driver"
)

const diagnosticSleepUnclassified uint64 = 1 << 63
const diagnosticSleepKnownErrors uint64 = (1 << 13) - 1

func recordSleepOldError(scope *diagnostics.Scope, prefix string, err error) {
	kinds := []error{ErrClosed, ErrRemoved, ErrPermission, ErrBusy, ErrUnsupported, ErrInvalidArgument, ErrInvalidReport, ErrStaleEndpoint, ErrTimeout, ErrIO, ErrResourceLimit, context.Canceled, context.DeadlineExceeded}
	var classes uint64
	for index, kind := range kinds {
		if errors.Is(err, kind) {
			classes |= 1 << index
		}
	}
	if err != nil && classes == 0 {
		classes = diagnosticSleepUnclassified
	}
	scope.Counter(prefix+"old_error_categories", classes)
	scope.Fact(prefix+"old_error_unclassified", classes == diagnosticSleepUnclassified)
	scope.Fact(prefix+"old_error_recorded", err != nil)
	count := uint64(0)
	if err != nil {
		count = 1
	}
	scope.Counter(prefix+"old_error_count", count)
	type code struct {
		domain string
		value  uint64
	}
	seen := make(map[code]bool)
	var walk func(error)
	walk = func(cause error) {
		if cause == nil {
			return
		}
		var native code
		switch value := cause.(type) {
		case *NativeError:
			native = code{value.Domain, value.Code}
		case *driver.Error:
			native = code{value.Domain, value.Code}
		}
		if native.domain != "" && !seen[native] {
			seen[native] = true
			scope.Native(diagnostics.NativeError{Operation: prefix + "old_session", Domain: native.domain, Code: native.value})
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
	scope.Counter(prefix+"old_native_error_count", uint64(len(seen)))
}
