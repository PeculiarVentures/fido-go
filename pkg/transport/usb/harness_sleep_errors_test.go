//go:build hid_diagnostics

package usb_test

import (
	"context"
	"errors"

	"github.com/PeculiarVentures/fido-go/internal/diagnostics"
	"github.com/PeculiarVentures/fido-go/internal/diagnostics/power"
	"github.com/PeculiarVentures/fido-go/pkg/hid"
	"github.com/PeculiarVentures/fido-go/pkg/transport/usb"
)

const usbSleepUnknownError uint64 = 1 << 63
const usbSleepKnownErrors uint64 = (1 << 13) - 1

func usbSleepKinds() []error {
	return []error{hid.ErrClosed, hid.ErrRemoved, hid.ErrPermission, hid.ErrBusy, hid.ErrUnsupported, hid.ErrInvalidArgument, hid.ErrInvalidReport, hid.ErrStaleEndpoint, hid.ErrTimeout, hid.ErrIO, hid.ErrResourceLimit, context.Canceled, context.DeadlineExceeded}
}

type usbSleepNativeCode struct {
	domain string
	code   uint64
}

func usbSleepNativeCodes(err error) []usbSleepNativeCode {
	var result []usbSleepNativeCode
	seen := make(map[usbSleepNativeCode]bool)
	var walk func(error)
	walk = func(cause error) {
		if cause == nil {
			return
		}
		var native usbSleepNativeCode
		switch value := cause.(type) {
		case *hid.NativeError:
			native = usbSleepNativeCode{value.Domain, value.Code}
		case *power.Error:
			native = usbSleepNativeCode{value.Domain, value.Code}
		}
		if native.domain != "" && !seen[native] {
			seen[native] = true
			result = append(result, native)
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
	return result
}

func usbSleepFailure(scope *diagnostics.Scope, message string, err error) error {
	if err == nil {
		return nil
	}
	safe := []error{errors.New(message)}
	var powerError *power.Error
	if errors.As(err, &powerError) {
		safe = append(safe, &power.Error{Op: message, Kind: powerError.Kind, Domain: powerError.Domain, Code: powerError.Code})
	}
	for _, kind := range usbSleepKinds() {
		if errors.Is(err, kind) {
			safe = append(safe, kind)
		}
	}
	for _, native := range usbSleepNativeCodes(err) {
		scope.Native(diagnostics.NativeError{Operation: message, Domain: native.domain, Code: native.code})
		safe = append(safe, &hid.NativeError{Domain: native.domain, Code: native.code})
	}
	if status, ok := diagnostics.Disposition(err); ok {
		if status == diagnostics.Inconclusive {
			safe = append(safe, diagnostics.InconclusiveReason("USB sleep diagnostic evidence is incomplete"))
		} else if status == diagnostics.Skip {
			safe = append(safe, diagnostics.SkipReason("USB sleep diagnostic prerequisite is unavailable"))
		}
	}
	return errors.Join(safe...)
}

func usbSleepExchangeStage(stage usb.ExchangeStage) uint64 {
	switch stage {
	case usb.StageINIT:
		return 1
	case usb.StagePING:
		return 2
	case usb.StageRequest:
		return 3
	case usb.StageResponse:
		return 4
	default:
		return 0
	}
}

func recordUSBSleepOldError(scope *diagnostics.Scope, prefix string, err error, completed uint64) bool {
	var classes uint64
	for index, kind := range usbSleepKinds() {
		if errors.Is(err, kind) {
			classes |= 1 << index
		}
	}
	if err != nil && classes == 0 {
		classes = usbSleepUnknownError
	}
	scope.Counter(prefix+"old_error_categories", classes)
	scope.Fact(prefix+"old_error_unclassified", classes == usbSleepUnknownError)
	scope.Fact(prefix+"old_error_recorded", err != nil)
	count := uint64(0)
	if err != nil {
		count = 1
	}
	scope.Counter(prefix+"old_error_count", count)
	codes := usbSleepNativeCodes(err)
	for _, native := range codes {
		scope.Native(diagnostics.NativeError{Operation: prefix + "old_exchange", Domain: native.domain, Code: native.code})
	}
	scope.Counter(prefix+"old_native_error_count", uint64(len(codes)))
	var exchange *usb.ExchangeError
	typed := errors.As(err, &exchange)
	scope.Fact(prefix+"old_exchange_error_present", typed)
	scope.Fact(prefix+"old_delivery_ambiguous", typed && exchange.Ambiguous)
	stage, outcome, packets := uint64(0), uint64(hid.OutcomeCompleted), completed
	if err != nil {
		outcome, packets = uint64(hid.OutcomeUnknown), 0
	}
	if typed {
		stage = usbSleepExchangeStage(exchange.Stage)
		outcome = uint64(exchange.Outcome)
		if exchange.PacketsSubmitted >= 0 {
			packets = uint64(exchange.PacketsSubmitted)
		} else {
			packets = ^uint64(0)
		}
	}
	scope.Counter(prefix+"old_exchange_stage", stage)
	scope.Counter(prefix+"old_write_outcome", outcome)
	scope.Counter(prefix+"old_packets_submitted", packets)
	return err == nil || typed && stage != 0
}
