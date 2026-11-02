//go:build darwin && cgo

// Package darwin implements native IOHIDDevice inventory and report I/O.
package darwin

/*
#cgo CFLAGS: -Wall -Wextra
#cgo LDFLAGS: -framework IOKit -framework CoreFoundation
#include "native.h"
#include <errno.h>
#include <stdlib.h>
*/
import "C"

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/driver"
	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/reportdesc"
)

// Enumerate returns all addressable Application collections, including those
// whose layout or bus is unsupported for I/O. It does not open device sessions.
func Enumerate(resolveStrings bool) (driver.Snapshot, error) {
	var requested C.int
	if resolveStrings {
		requested = 1
	}
	native := C.hid_enumerate(requested)
	if native == nil {
		return driver.Snapshot{}, failure("enumerate", driver.KindResourceLimit, "native inventory allocation failed")
	}
	defer C.hid_inventory_free(native)
	snapshot := driver.Snapshot{Complete: native.complete != 0}
	if native.error != 0 {
		return snapshot, ioError("enumerate", native.error)
	}
	if !snapshot.Complete {
		kind := driver.KindIO
		if native.limited != 0 {
			kind = driver.KindResourceLimit
		}
		snapshot.Warnings = append(snapshot.Warnings, failure("enumerate", kind, "native inventory traversal incomplete"))
	}
	for _, entry := range unsafe.Slice(native.entries, int(native.count)) {
		if len(snapshot.Endpoints) == driver.MaxInventoryEndpoints {
			snapshot.Complete = false
			snapshot.Warnings = append(snapshot.Warnings, failure("enumerate", driver.KindResourceLimit, "inventory endpoint limit reached"))
			return snapshot, nil
		}
		base := endpoint(&entry)
		description, err := describe(&entry)
		if err != nil || len(description.Collections) == 0 {
			// The interface remains visible even when its Application selectors
			// cannot be resolved. This exact interface address cannot be opened.
			base.ID = endpointID(uint64(entry.registry_id), -1)
			snapshot.Endpoints = append(snapshot.Endpoints, base)
			snapshot.Complete = false
			if err == nil {
				err = errors.New("no Application collections in descriptor")
			}
			snapshot.Warnings = append(snapshot.Warnings, &driver.Error{
				Op: "enumerate", Kind: driver.KindIO,
				Message: "cannot resolve Application collections for " + base.ID + ": " + err.Error(), Cause: err,
			})
			continue
		}
		for _, collection := range description.Collections {
			if len(snapshot.Endpoints) == driver.MaxInventoryEndpoints {
				snapshot.Complete = false
				snapshot.Warnings = append(snapshot.Warnings, failure("enumerate", driver.KindResourceLimit, "inventory endpoint limit reached"))
				return snapshot, nil
			}
			ep := base
			ep.ID = endpointID(uint64(entry.registry_id), collection.Index)
			ep.Usage = driver.Field[driver.Usage]{Known: true, Value: collection.Usage}
			snapshot.Endpoints = append(snapshot.Endpoints, ep)
		}
	}
	sort.Slice(snapshot.Endpoints, func(i, j int) bool { return snapshot.Endpoints[i].ID < snapshot.Endpoints[j].ID })
	return snapshot, nil
}

func endpoint(entry *C.hid_entry) driver.Endpoint {
	known := uint32(entry.known)
	return driver.Endpoint{
		Path:         C.GoString(&entry.path[0]),
		VendorID:     driver.Field[uint16]{Value: uint16(entry.vendor), Known: known&1 != 0},
		ProductID:    driver.Field[uint16]{Value: uint16(entry.product), Known: known&2 != 0},
		Interface:    driver.Field[int]{Value: int(entry.interface_number), Known: known&4 != 0},
		Bus:          driver.Bus(entry.bus),
		Serial:       driver.Field[string]{Value: C.GoString(&entry.serial[0]), Known: known&8 != 0},
		Manufacturer: driver.Field[string]{Value: C.GoString(&entry.manufacturer[0]), Known: known&16 != 0},
		Product:      driver.Field[string]{Value: C.GoString(&entry.product_name[0]), Known: known&32 != 0},
	}
}

func describe(entry *C.hid_entry) (reportdesc.Description, error) {
	if entry.descriptor_length == -2 {
		return reportdesc.Description{}, failure("descriptor", driver.KindResourceLimit, "native descriptor allocation failed")
	}
	if entry.descriptor_length < 1 || entry.descriptor_length > driver.MaxDescriptorSize {
		return reportdesc.Description{}, errors.New("report descriptor unavailable or exceeds supported bound")
	}
	return reportdesc.Parse(C.GoBytes(unsafe.Pointer(entry.descriptor), entry.descriptor_length))
}

func endpointID(registryID uint64, collection int) string {
	return fmt.Sprintf("darwin:%016x:%d", registryID, collection)
}

func address(id string) (uint64, int, error) {
	parts := strings.Split(id, ":")
	if len(parts) != 3 || parts[0] != "darwin" {
		return 0, 0, failure("open", driver.KindInvalidArgument, "invalid endpoint ID")
	}
	registryID, err := strconv.ParseUint(parts[1], 16, 64)
	index, indexErr := strconv.Atoi(parts[2])
	if err != nil || indexErr != nil || registryID == 0 || index < -1 || endpointID(registryID, index) != id {
		return 0, 0, failure("open", driver.KindInvalidArgument, "invalid endpoint ID")
	}
	return registryID, index, nil
}

// Open resolves exactly the supplied registry-entry/collection selector and
// verifies every known expected descriptor field before opening native I/O.
func Open(expected driver.Endpoint) (driver.Device, error) {
	registryID, index, err := address(expected.ID)
	if err != nil {
		return nil, err
	}
	var resolveStrings C.int
	if expected.Serial.Known || expected.Manufacturer.Known || expected.Product.Known {
		resolveStrings = 1
	}
	var code C.uint32_t
	entry := C.hid_lookup(C.uint64_t(registryID), resolveStrings, &code)
	if entry == nil {
		return nil, ioError("open", code)
	}
	defer C.hid_entry_free(entry)
	description, err := describe(entry)
	if err != nil {
		return nil, &driver.Error{Op: "open", Kind: driver.KindUnsupported, Cause: err}
	}
	var selected *reportdesc.Collection
	for i := range description.Collections {
		if description.Collections[i].Index == index {
			selected = &description.Collections[i]
			break
		}
	}
	if selected == nil {
		kind := driver.KindStaleEndpoint
		if index == -1 {
			kind = driver.KindUnsupported
		}
		return nil, failure("open", kind, "Application collection unavailable")
	}
	actual := endpoint(entry)
	actual.ID = endpointID(uint64(entry.registry_id), selected.Index)
	actual.Usage = driver.Field[driver.Usage]{Known: true, Value: selected.Usage}
	if !matches(expected, actual) {
		return nil, failure("open", driver.KindStaleEndpoint, "endpoint descriptor changed")
	}
	if !selected.Supported || actual.Bus != driver.BusUSB || selected.Usage != (driver.Usage{Page: 0xf1d0, ID: 1}) {
		return nil, failure("open", driver.KindUnsupported, "only unambiguous USB FIDO Input/Output collections are qualified")
	}
	layout := selected.Layout
	var threadError C.int
	connection := C.hid_connect(entry, C.uint8_t(layout.Input.ID), C.int(layout.Input.Size),
		C.uint8_t(layout.Output.ID), C.int(layout.Output.Size), &code, &threadError)
	if connection == nil {
		if threadError != 0 {
			return nil, pthreadError("open", threadError)
		}
		return nil, ioError("open", code)
	}
	return &device{native: connection, endpoint: actual, layout: layout}, nil
}

func equalField[T comparable](expected, actual driver.Field[T]) bool {
	return !expected.Known || (actual.Known && expected.Value == actual.Value)
}

func matches(expected, actual driver.Endpoint) bool {
	return expected.ID == actual.ID &&
		equalField(expected.VendorID, actual.VendorID) && equalField(expected.ProductID, actual.ProductID) &&
		equalField(expected.Usage, actual.Usage) && equalField(expected.Interface, actual.Interface) &&
		equalField(expected.Serial, actual.Serial) && equalField(expected.Manufacturer, actual.Manufacturer) &&
		equalField(expected.Product, actual.Product) && (expected.Bus == driver.BusUnknown || expected.Bus == actual.Bus)
}

type device struct {
	native   *C.hid_connection
	endpoint driver.Endpoint
	layout   driver.Layout
}

func (d *device) Endpoint() driver.Endpoint { return d.endpoint }
func (d *device) Layout() driver.Layout     { return d.layout }

func (d *device) Read(wait time.Duration) (driver.Report, error) {
	if wait < 0 {
		return driver.Report{}, failure("read", driver.KindInvalidArgument, "negative wait")
	}
	var report C.hid_report
	var code C.uint32_t
	status := C.hid_read(d.native, C.int64_t(wait), &report, &code)
	if code != 0 {
		return driver.Report{}, ioError("read", code)
	}
	if status != 0 {
		if status > 0 && status != C.ETIMEDOUT {
			return driver.Report{}, pthreadError("read", status)
		}
		kind, message := driver.KindIO, "native input wait failed"
		switch status {
		case C.ETIMEDOUT:
			kind, message = driver.KindTimeout, "input wait timeout"
		case -2:
			message = "native input queue overflow"
		case -3:
			message = "input report length or ID does not match descriptor"
		case -4:
			message = "writer retired after signal mask restoration failure"
		case -5:
			kind, message = driver.KindClosed, "connection closed"
		}
		return driver.Report{}, failure("read", kind, message)
	}
	return driver.Report{ID: d.layout.Input.ID,
		Data: C.GoBytes(unsafe.Pointer(&report.data[0]), report.length)}, nil
}

func (d *device) Write(report driver.Report) (driver.WriteResult, error) {
	result := driver.WriteResult{Outcome: driver.OutcomeNotSubmitted}
	if report.ID != d.layout.Output.ID || len(report.Data) != d.layout.Output.Size {
		return result, failure("write", driver.KindInvalidReport, "output report does not match descriptor")
	}
	// Even if the core caller returns on cancellation, C owns this copy until
	// the native pthread has completed. No Go pointer is stored in native state.
	buffer := C.CBytes(report.Data)
	if buffer == nil {
		return result, failure("write", driver.KindResourceLimit, "output buffer allocation failed")
	}
	defer C.free(buffer)
	var native C.hid_write_result
	C.hid_write(d.native, (*C.uint8_t)(buffer), C.int(len(report.Data)), &native)
	if native.submitted != 0 {
		result.Outcome = driver.OutcomeUnknown
	}
	if native.completed != 0 {
		result.Outcome = driver.OutcomeCompleted
	}
	var causes []error
	if native.io != 0 {
		causes = append(causes, ioError("write", native.io))
	}
	if native.setup_error != 0 {
		causes = append(causes, pthreadError("write: block SIGURG", native.setup_error))
	}
	if native.restore_error != 0 {
		causes = append(causes, pthreadError("write: restore signal mask", native.restore_error))
	}
	return result, errors.Join(causes...)
}

func (d *device) Close() error {
	code := C.hid_disconnect(d.native)
	d.native = nil
	if code != 0 {
		return ioError("close", code)
	}
	return nil
}

func failure(op string, kind driver.Kind, message string) error {
	return &driver.Error{Op: op, Kind: kind, Message: message}
}

func pthreadError(op string, code C.int) error {
	return &driver.Error{Op: op, Kind: driver.KindIO, Domain: "pthread", Code: uint64(code), Message: syscall.Errno(code).Error()}
}

func ioError(op string, code C.uint32_t) error {
	kind := driver.KindIO
	switch int32(code) {
	case C.kIOReturnNoDevice, C.kIOReturnOffline:
		kind = driver.KindRemoved
	case C.kIOReturnNotPrivileged, C.kIOReturnNotPermitted:
		kind = driver.KindPermission
	case C.kIOReturnExclusiveAccess, C.kIOReturnBusy:
		kind = driver.KindBusy
	case C.kIOReturnUnsupported:
		kind = driver.KindUnsupported
	case C.kIOReturnNoMemory, C.kIOReturnNoResources:
		kind = driver.KindResourceLimit
	case C.kIOReturnNotOpen:
		kind = driver.KindClosed
	}
	// In particular kIOReturnError (0xE00002BC) stays KindIO. It is not
	// evidence that a device was removed or that a report was undelivered.
	return &driver.Error{Op: op, Kind: kind, Domain: "iokit", Code: uint64(code), Message: C.GoString(C.hid_error_message(code))}
}
