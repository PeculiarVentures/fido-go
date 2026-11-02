//go:build windows

package windows

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/driver"
	"golang.org/x/sys/windows"
)

var testFIDOUsage = driver.Usage{Page: 0xf1d0, ID: 1}

func selectFIDO(ep driver.Endpoint) (match, unknown bool) {
	if ep.Bus != driver.BusUnknown && ep.Bus != driver.BusUSB || ep.Usage.Known && ep.Usage.Value != testFIDOUsage {
		return false, false
	}
	unknown = ep.Bus == driver.BusUnknown || !ep.Usage.Known
	return !unknown, unknown
}

func TestInventoryExcludesUnrelatedInterfacesBeforeCreateFile(t *testing.T) {
	keyboard := driver.Endpoint{ID: "keyboard", Path: "denied", Bus: driver.BusUSB, Usage: driver.Field[driver.Usage]{Known: true, Value: driver.Usage{Page: 1, ID: 6}}}
	bluetooth := driver.Endpoint{ID: "bluetooth", Path: "also-denied", Bus: driver.BusBluetooth}
	fido := driver.Endpoint{ID: "fido", Path: "fido-path", Bus: driver.BusUSB, Usage: driver.Field[driver.Usage]{Known: true, Value: testFIDOUsage}}
	var opened []string
	closed := 0
	system := inventorySystem{
		open: func(path string) (windows.Handle, error) {
			opened = append(opened, path)
			if path != fido.Path {
				return windows.InvalidHandle, nativeError("CreateFile", windows.ERROR_ACCESS_DENIED)
			}
			return 1, nil
		},
		metadata: func(_ windows.Handle, ep *driver.Endpoint, resolveStrings bool) error {
			if !resolveStrings {
				t.Error("optional strings were not requested")
			}
			ep.Product = driver.Field[string]{Known: true, Value: "key"}
			return nil
		},
		close: func(windows.Handle) error { closed++; return nil },
	}
	snapshot := driver.Snapshot{Complete: true}
	for _, endpoint := range []driver.Endpoint{keyboard, bluetooth, fido} {
		appendInventoryEndpoint(&snapshot, endpoint, true, selectFIDO, system)
	}
	if !snapshot.Complete || len(snapshot.Warnings) != 0 || len(snapshot.Endpoints) != 1 || snapshot.Endpoints[0].Product.Value != "key" || len(opened) != 1 || opened[0] != fido.Path || closed != 1 {
		t.Fatalf("snapshot=%+v opened=%v closed=%d", snapshot, opened, closed)
	}
}

func TestInventoryRetainsInaccessibleCandidates(t *testing.T) {
	for _, tc := range []struct {
		name           string
		endpoint       driver.Endpoint
		selectEndpoint func(driver.Endpoint) (bool, bool)
	}{
		{"matching FIDO", driver.Endpoint{Bus: driver.BusUSB, Usage: driver.Field[driver.Usage]{Known: true, Value: testFIDOUsage}}, selectFIDO},
		{"unfiltered keyboard", driver.Endpoint{Bus: driver.BusUSB, Usage: driver.Field[driver.Usage]{Known: true, Value: driver.Usage{Page: 1, ID: 6}}}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snapshot := driver.Snapshot{Complete: true}
			ep := tc.endpoint
			ep.ID, ep.Path = "candidate", `\\?\hid#vid_1234&pid_5678#candidate`
			appendInventoryEndpoint(&snapshot, ep, false, tc.selectEndpoint, inventorySystem{
				open: func(string) (windows.Handle, error) {
					return windows.InvalidHandle, nativeError("CreateFile", windows.ERROR_ACCESS_DENIED)
				},
				metadata: func(windows.Handle, *driver.Endpoint, bool) error { t.Fatal("inspected invalid handle"); return nil },
				close:    func(windows.Handle) error { t.Fatal("closed invalid handle"); return nil },
			})
			if snapshot.Complete || len(snapshot.Endpoints) != 1 || snapshot.Endpoints[0] != ep || len(snapshot.Warnings) != 1 || !errors.Is(snapshot.Warnings[0], windows.ERROR_ACCESS_DENIED) {
				t.Fatalf("snapshot=%+v", snapshot)
			}
			var native *driver.Error
			if !strings.Contains(snapshot.Warnings[0].Error(), strconv.Quote(ep.Path)) || !errors.As(snapshot.Warnings[0], &native) || native.Kind != driver.KindPermission || native.Domain != "win32" || native.Code != uint64(windows.ERROR_ACCESS_DENIED) {
				t.Fatalf("warning lost endpoint or native permission details: %v", snapshot.Warnings[0])
			}
		})
	}
}

func TestInventoryDoesNotOpenUnclassifiedCollections(t *testing.T) {
	for _, ep := range []driver.Endpoint{
		{Bus: driver.BusUSB},
		{Usage: driver.Field[driver.Usage]{Known: true, Value: testFIDOUsage}},
		{},
	} {
		snapshot := driver.Snapshot{Complete: true}
		ep.ID, ep.Path = "unknown", "possibly-keyboard"
		appendInventoryEndpoint(&snapshot, ep, true, selectFIDO, inventorySystem{
			open: func(string) (windows.Handle, error) { t.Fatal("opened unclassified collection"); return 0, nil },
		})
		if snapshot.Complete || len(snapshot.Endpoints) != 1 || snapshot.Endpoints[0] != ep || len(snapshot.Warnings) != 1 {
			t.Fatalf("snapshot=%+v", snapshot)
		}
	}
}

func TestInventoryRefreshesHandleMetadataForKnownMatches(t *testing.T) {
	for _, tc := range []struct {
		name     string
		usage    driver.Usage
		failure  error
		complete bool
		count    int
	}{
		{"matching", testFIDOUsage, nil, true, 1},
		{"matching with inspection failure", testFIDOUsage, windows.ERROR_GEN_FAILURE, false, 1},
		{"excluded with unrelated inspection failure", driver.Usage{Page: 1, ID: 6}, windows.ERROR_GEN_FAILURE, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snapshot := driver.Snapshot{Complete: true}
			closed := false
			appendInventoryEndpoint(&snapshot, driver.Endpoint{ID: "candidate", Path: "path", Bus: driver.BusUSB, Usage: driver.Field[driver.Usage]{Known: true, Value: testFIDOUsage}}, false, selectFIDO, inventorySystem{
				open: func(string) (windows.Handle, error) { return 1, nil },
				metadata: func(_ windows.Handle, ep *driver.Endpoint, resolveStrings bool) error {
					if resolveStrings {
						t.Error("unrequested strings resolved")
					}
					ep.Usage = driver.Field[driver.Usage]{Known: true, Value: tc.usage}
					return tc.failure
				},
				close: func(windows.Handle) error { closed = true; return nil },
			})
			if !closed || snapshot.Complete != tc.complete || len(snapshot.Endpoints) != tc.count || (len(snapshot.Warnings) == 0) != tc.complete {
				t.Fatalf("snapshot=%+v closed=%v", snapshot, closed)
			}
		})
	}
}

func TestUsageFromPropertiesRequiresBothTypedValues(t *testing.T) {
	for _, tc := range []struct {
		name    string
		invalid uint32
		kind    windows.DEVPROPTYPE
		size    uint32
		err     error
		known   bool
	}{
		{"valid", 0, windows.DEVPROP_TYPE_UINT16, 2, nil, true},
		{"missing page", 2, windows.DEVPROP_TYPE_UINT16, 2, windows.ERROR_NOT_FOUND, false},
		{"denied id", 3, windows.DEVPROP_TYPE_UINT16, 2, windows.ERROR_ACCESS_DENIED, false},
		{"page wrong type", 2, windows.DEVPROP_TYPE_UINT32, 2, nil, false},
		{"id wrong type", 3, windows.DEVPROP_TYPE_UINT16 | windows.DEVPROP_TYPEMOD_LIST, 2, nil, false},
		{"page too short", 2, windows.DEVPROP_TYPE_UINT16, 1, nil, false},
		{"id too long", 3, windows.DEVPROP_TYPE_UINT16, 4, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			usage := usageFromProperties(func(property uint32) (uint16, windows.DEVPROPTYPE, uint32, error) {
				calls++
				if property != uint32(calls+1) {
					t.Fatalf("unexpected HID property: %d", property)
				}
				value := uint16(0xf1d0)
				if property == 3 {
					value = 1
				}
				if property == tc.invalid {
					return value, tc.kind, tc.size, tc.err
				}
				return value, windows.DEVPROP_TYPE_UINT16, 2, nil
			})
			if calls != 2 || usage.Known != tc.known || tc.known && usage.Value != testFIDOUsage {
				t.Fatalf("usage=%+v calls=%d", usage, calls)
			}
		})
	}
	usage := usageFromProperties(func(uint32) (uint16, windows.DEVPROPTYPE, uint32, error) {
		return 0, windows.DEVPROP_TYPE_UINT16, 2, nil
	})
	if !usage.Known || usage.Value != (driver.Usage{}) {
		t.Fatalf("zero usage must be known: %+v", usage)
	}
}

func TestInterfaceHardwareIDsRequireTypedValues(t *testing.T) {
	for _, property := range []uint32{hidVendorIDProperty, hidProductIDProperty} {
		for _, tc := range []struct {
			name  string
			kind  windows.DEVPROPTYPE
			size  uint32
			err   error
			known bool
		}{
			{"valid", windows.DEVPROP_TYPE_UINT16, 2, nil, true},
			{"missing", windows.DEVPROP_TYPE_UINT16, 2, windows.ERROR_NOT_FOUND, false},
			{"denied", windows.DEVPROP_TYPE_UINT16, 2, windows.ERROR_ACCESS_DENIED, false},
			{"wrong type", windows.DEVPROP_TYPE_UINT32, 2, nil, false},
			{"list", windows.DEVPROP_TYPE_UINT16 | windows.DEVPROP_TYPEMOD_LIST, 2, nil, false},
			{"too short", windows.DEVPROP_TYPE_UINT16, 1, nil, false},
			{"too long", windows.DEVPROP_TYPE_UINT16, 4, nil, false},
		} {
			t.Run(strconv.FormatUint(uint64(property), 10)+"/"+tc.name, func(t *testing.T) {
				ep := driver.Endpoint{}
				metadataFromInterfaceProperties(&ep, func(id uint32) (uint16, windows.DEVPROPTYPE, uint32, error) {
					if id == property {
						// Zero is a valid, known VID/PID and must not be confused
						// with a missing or malformed property.
						return 0, tc.kind, tc.size, tc.err
					}
					return 0x1234, windows.DEVPROP_TYPE_UINT16, 2, nil
				})
				field, other := ep.VendorID, ep.ProductID
				if property == hidProductIDProperty {
					field, other = other, field
				}
				if field.Known != tc.known || field.Value != 0 || !other.Known || other.Value != 0x1234 {
					t.Fatalf("vendor=%+v product=%+v", ep.VendorID, ep.ProductID)
				}
			})
		}
	}
}

func TestInterfaceHardwareIDsPreservePnPFallback(t *testing.T) {
	for _, validProperties := range []bool{false, true} {
		ep := driver.Endpoint{}
		hardwareFields(`HID\VID_1111&PID_2222`, &ep)
		metadataFromInterfaceProperties(&ep, func(property uint32) (uint16, windows.DEVPROPTYPE, uint32, error) {
			if !validProperties {
				return 0, 0, 0, windows.ERROR_NOT_FOUND
			}
			return uint16(property), windows.DEVPROP_TYPE_UINT16, 2, nil
		})
		vendor, product := uint16(0x1111), uint16(0x2222)
		if validProperties {
			vendor, product = hidVendorIDProperty, hidProductIDProperty
		}
		if !ep.VendorID.Known || ep.VendorID.Value != vendor || !ep.ProductID.Known || ep.ProductID.Value != product {
			t.Fatalf("validProperties=%v endpoint=%+v", validProperties, ep)
		}
	}
}

func TestInventoryFiltersHardwareIDsWithoutPnPVIDPID(t *testing.T) {
	for _, tc := range []struct {
		name            string
		vendor, product uint16
		missing         uint32
		opened          bool
		complete        bool
		count           int
	}{
		{"matching", 0x045e, 0x0010, 0, true, true, 1},
		{"different vendor", 0x1234, 0x0010, 0, false, true, 0},
		{"different product", 0x045e, 0x5678, 0, false, true, 0},
		{"missing vendor", 0x045e, 0x0010, hidVendorIDProperty, false, false, 1},
		{"missing product", 0x045e, 0x0010, hidProductIDProperty, false, false, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ep := driver.Endpoint{ID: "i2c", Path: "i2c-interface"}
			hardwareFields(`HID\VEN_MSFT&DEV_0010`, &ep)
			if ep.VendorID.Known || ep.ProductID.Known {
				t.Fatal("fixture unexpectedly supplied PnP VID/PID")
			}
			metadataFromInterfaceProperties(&ep, func(property uint32) (uint16, windows.DEVPROPTYPE, uint32, error) {
				if property == tc.missing {
					return 0, 0, 0, windows.ERROR_NOT_FOUND
				}
				value := uint16(1)
				if property == hidVendorIDProperty {
					value = tc.vendor
				} else if property == hidProductIDProperty {
					value = tc.product
				}
				return value, windows.DEVPROP_TYPE_UINT16, 2, nil
			})
			selectIDs := func(candidate driver.Endpoint) (bool, bool) {
				if candidate.VendorID.Known && candidate.VendorID.Value != 0x045e || candidate.ProductID.Known && candidate.ProductID.Value != 0x0010 {
					return false, false
				}
				unknown := !candidate.VendorID.Known || !candidate.ProductID.Known
				return !unknown, unknown
			}
			opened, closed := false, false
			snapshot := driver.Snapshot{Complete: true}
			appendInventoryEndpoint(&snapshot, ep, false, selectIDs, inventorySystem{
				open: func(string) (windows.Handle, error) { opened = true; return 1, nil },
				metadata: func(_ windows.Handle, candidate *driver.Endpoint, _ bool) error {
					if !candidate.VendorID.Known || !candidate.ProductID.Known {
						t.Fatal("opened before interface VID/PID were resolved")
					}
					return nil
				},
				close: func(windows.Handle) error { closed = true; return nil },
			})
			if opened != tc.opened || closed != tc.opened || snapshot.Complete != tc.complete || len(snapshot.Endpoints) != tc.count || (len(snapshot.Warnings) == 0) != tc.complete {
				t.Fatalf("opened=%v closed=%v snapshot=%+v", opened, closed, snapshot)
			}
		})
	}
}
