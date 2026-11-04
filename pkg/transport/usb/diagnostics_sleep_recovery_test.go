//go:build hid_diagnostics

package usb_test

import (
	"github.com/PeculiarVentures/fido-go/pkg/hid"
	"testing"
)

func usbSleepTestEndpoint(id hid.EndpointID) hid.Endpoint {
	return hid.Endpoint{ID: id, Bus: hid.BusUSB, VendorID: hid.Field[uint16]{Known: true, Value: 0x08e6}, ProductID: hid.Field[uint16]{Known: true, Value: 0x34d2}, Usage: hid.Field[hid.Usage]{Known: true, Value: hid.Usage{Page: 0xf1d0, ID: 1}}, Interface: hid.Field[int]{Known: true}}
}
func TestUSBSleepRecoveryReservesRetainedAddressesAndRejectsAmbiguity(t *testing.T) {
	a, b := usbSleepTestEndpoint("private-a"), usbSleepTestEndpoint("private-b")
	x, y := usbSleepTestEndpoint("private-x"), usbSleepTestEndpoint("private-y")
	got, err := selectUSBSleepRecovery([]hid.Endpoint{a, b}, []hid.Endpoint{b, a})
	if err != nil || len(got) != 2 || got[0].ID != a.ID || got[1].ID != b.ID {
		t.Fatalf("retained addresses not reserved: %v", err)
	}
	got, err = selectUSBSleepRecovery([]hid.Endpoint{a, b}, []hid.Endpoint{b, x})
	if err != nil || len(got) != 2 || got[0].ID != x.ID || got[1].ID != b.ID {
		t.Fatalf("unique unclaimed recovery failed: %v", err)
	}
	if got, err = selectUSBSleepRecovery([]hid.Endpoint{a, b}, []hid.Endpoint{x, y}); err == nil || len(got) != 0 {
		t.Fatal("two changed identical candidates auto-selected")
	}
	changed := b
	changed.Interface.Value = 1
	if got, err = selectUSBSleepRecovery([]hid.Endpoint{a, b}, []hid.Endpoint{a, changed}); err == nil || len(got) != 0 {
		t.Fatal("retained address with metadata mismatch accepted")
	}
	if got, err = selectUSBSleepRecovery([]hid.Endpoint{a, b}, []hid.Endpoint{a, a}); err == nil || len(got) != 0 {
		t.Fatal("duplicate inventory accepted")
	}
}
