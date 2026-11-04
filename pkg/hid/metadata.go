package hid

import "github.com/PeculiarVentures/fido-go/pkg/hid/internal/driver"

func publicField[T any](v driver.Field[T]) Field[T] { return Field[T]{Value: v.Value, Known: v.Known} }
func nativeField[T any](v Field[T]) driver.Field[T] {
	return driver.Field[T]{Value: v.Value, Known: v.Known}
}
func publicEndpoint(e driver.Endpoint) Endpoint {
	return Endpoint{ID: EndpointID(e.ID), Path: e.Path, VendorID: publicField(e.VendorID), ProductID: publicField(e.ProductID), Usage: Field[Usage]{Value: Usage{Page: e.Usage.Value.Page, ID: e.Usage.Value.ID}, Known: e.Usage.Known}, Interface: publicField(e.Interface), Bus: Bus(e.Bus), Serial: publicField(e.Serial), Manufacturer: publicField(e.Manufacturer), Product: publicField(e.Product)}
}
func nativeEndpoint(e Endpoint) driver.Endpoint {
	return driver.Endpoint{ID: string(e.ID), Path: e.Path, VendorID: nativeField(e.VendorID), ProductID: nativeField(e.ProductID), Usage: driver.Field[driver.Usage]{Value: driver.Usage{Page: e.Usage.Value.Page, ID: e.Usage.Value.ID}, Known: e.Usage.Known}, Interface: nativeField(e.Interface), Bus: driver.Bus(e.Bus), Serial: nativeField(e.Serial), Manufacturer: nativeField(e.Manufacturer), Product: nativeField(e.Product)}
}
func publicLayout(l driver.Layout) ReportLayout {
	return ReportLayout{Input: ReportSpec{ID: l.Input.ID, Size: l.Input.Size}, Output: ReportSpec{ID: l.Output.ID, Size: l.Output.Size}}
}
func matchesField[T comparable](expected, actual Field[T]) bool {
	return !expected.Known || actual.Known && expected.Value == actual.Value
}
func matchesEndpoint(expected, actual Endpoint) bool {
	return expected.ID == actual.ID && (expected.Path == "" || expected.Path == actual.Path) &&
		matchesField(expected.VendorID, actual.VendorID) && matchesField(expected.ProductID, actual.ProductID) && matchesField(expected.Usage, actual.Usage) && matchesField(expected.Interface, actual.Interface) && matchesField(expected.Serial, actual.Serial) && matchesField(expected.Manufacturer, actual.Manufacturer) && matchesField(expected.Product, actual.Product) && (expected.Bus == BusUnknown || expected.Bus == actual.Bus)
}
func clonePointer[T any](v *T) *T {
	if v == nil {
		return nil
	}
	copy := *v
	return &copy
}
func cloneFilter(f Filter) Filter {
	return Filter{VendorID: clonePointer(f.VendorID), ProductID: clonePointer(f.ProductID), Usage: clonePointer(f.Usage), Bus: clonePointer(f.Bus)}
}
func matchFilter(e Endpoint, f Filter) (match, unknown bool) {
	match = true
	check := func(requested, known, equal bool) {
		if !requested {
			return
		}
		if !known {
			unknown = true
		} else if !equal {
			match = false
		}
	}
	if f.VendorID != nil {
		check(true, e.VendorID.Known, e.VendorID.Value == *f.VendorID)
	}
	if f.ProductID != nil {
		check(true, e.ProductID.Known, e.ProductID.Value == *f.ProductID)
	}
	if f.Usage != nil {
		check(true, e.Usage.Known, e.Usage.Value == *f.Usage)
	}
	if f.Bus != nil {
		check(true, e.Bus != BusUnknown, e.Bus == *f.Bus)
	}
	if !match {
		return false, false
	}
	return !unknown, unknown
}

// Caller-provided metadata cannot cause an unbounded native string conversion.
func boundedEndpoint(e Endpoint) bool {
	for _, value := range []string{string(e.ID), e.Path, e.Serial.Value, e.Manufacturer.Value, e.Product.Value} {
		if len(value) > driver.MaxMetadataSize {
			return false
		}
	}
	return true
}
