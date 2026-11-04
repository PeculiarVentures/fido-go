//go:build hid_diagnostics

package usb_test

import (
	"errors"

	"github.com/PeculiarVentures/fido-go/internal/diagnostics"
	"github.com/PeculiarVentures/fido-go/pkg/hid"
)

// Resolve all retained addresses before matching any absent one. In particular,
// two identical stable endpoints reserve themselves rather than competing in a
// model-only search. This returns selectors only and never opens a candidate.
func selectUSBSleepRecovery(expected, current []hid.Endpoint) ([]hid.Endpoint, error) {
	byID := make(map[hid.EndpointID]hid.Endpoint, len(current))
	for _, endpoint := range current {
		if endpoint.ID == "" {
			return nil, errors.New("USB sleep recovery inventory contains an empty address")
		}
		if _, duplicate := byID[endpoint.ID]; duplicate {
			return nil, errors.New("USB sleep recovery inventory contains duplicate addresses")
		}
		byID[endpoint.ID] = endpoint
	}
	result := make([]hid.Endpoint, len(expected))
	claimed := make(map[hid.EndpointID]bool, len(expected))
	oldSeen := make(map[hid.EndpointID]bool, len(expected))
	for index, old := range expected {
		if old.ID == "" || oldSeen[old.ID] {
			return nil, errors.New("USB sleep recovery selection contains an empty or duplicate address")
		}
		oldSeen[old.ID] = true
		if retained, present := byID[old.ID]; present {
			if !sameUSBSleepMetadata(old, retained, true) {
				return nil, diagnostics.InconclusiveReason("retained USB address changed its known metadata after wake")
			}
			result[index] = retained
			claimed[retained.ID] = true
		}
	}
	for index, old := range expected {
		if result[index].ID != "" {
			continue
		}
		var candidate hid.Endpoint
		matches := 0
		for _, observed := range current {
			if !claimed[observed.ID] && sameUSBSleepMetadata(old, observed, false) {
				candidate = observed
				matches++
			}
		}
		if matches != 1 {
			return nil, diagnostics.InconclusiveReason("absent USB address has no unique unclaimed recovery candidate after wake")
		}
		result[index] = candidate
		claimed[candidate.ID] = true
	}
	return result, nil
}

func sameUSBSleepMetadata(expected, actual hid.Endpoint, retained bool) bool {
	usage := hid.Usage{Page: 0xf1d0, ID: 1}
	if expected.Bus != hid.BusUSB || actual.Bus != hid.BusUSB || !expected.Usage.Known || !actual.Usage.Known || expected.Usage.Value != usage || actual.Usage.Value != usage || !expected.VendorID.Known || !actual.VendorID.Known || !expected.ProductID.Known || !actual.ProductID.Known || expected.VendorID.Value != actual.VendorID.Value || expected.ProductID.Value != actual.ProductID.Value {
		return false
	}
	if retained && expected.Path != "" && expected.Path != actual.Path {
		return false
	}
	return usbSleepFieldMatches(expected.Interface, actual.Interface) && usbSleepFieldMatches(expected.Serial, actual.Serial) && usbSleepFieldMatches(expected.Manufacturer, actual.Manufacturer) && usbSleepFieldMatches(expected.Product, actual.Product)
}
func usbSleepFieldMatches[T comparable](expected, actual hid.Field[T]) bool {
	return !expected.Known || actual.Known && expected.Value == actual.Value
}
