package usb

import (
	"context"
	"errors"
	"fmt"
	"reflect"

	"github.com/PeculiarVentures/fido-go/pkg/hid"
	"github.com/PeculiarVentures/fido-go/pkg/transport"
)

const (
	hidReportSize       = 64
	hidBroadcastCID     = 0xffffffff
	hidCommandInit      = 0x86
	hidCommandMsg       = 0x83
	hidCommandCBOR      = 0x90
	hidCommandKeepalive = 0xbb
	hidCommandError     = 0xbf
	fidoUsagePage       = 0xf1d0
	fidoUsage           = 0x01
)

// HIDBackend discovers and opens native USB HID FIDO endpoints.
type HIDBackend struct{ backend hid.Backend }

// HIDError reports a definitive CTAPHID ERROR response from an authenticator.
type HIDError struct{ Code byte }

// Error returns the wire-level CTAPHID error code.
func (err *HIDError) Error() string {
	if err == nil {
		return "transport/usb: <nil>"
	}
	return fmt.Sprintf("transport/usb: CTAPHID error 0x%02x", err.Code)
}

// NewHIDBackend creates a backend without performing native I/O.
func NewHIDBackend() *HIDBackend { return &HIDBackend{backend: hid.New()} }

// NewHIDBackendWithHID creates a USB adapter over an injected HID backend.
func NewHIDBackendWithHID(backend hid.Backend) (*HIDBackend, error) {
	if backend == nil {
		return nil, fmt.Errorf("transport/usb: HID backend is required: %w", hid.ErrInvalidArgument)
	}
	value := reflect.ValueOf(backend)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if value.IsNil() {
			return nil, fmt.Errorf("transport/usb: HID backend is required: %w", hid.ErrInvalidArgument)
		}
	}
	return &HIDBackend{backend: backend}, nil
}

// Kind returns the USB transport kind.
func (backend *HIDBackend) Kind() transport.Kind { return transport.KindUSB }

func (backend *HIDBackend) native() hid.Backend {
	if backend == nil || backend.backend == nil {
		return hid.New()
	}
	return backend.backend
}

func fidoOptions() hid.EnumerateOptions {
	bus := hid.BusUSB
	usage := hid.Usage{Page: fidoUsagePage, ID: fidoUsage}
	return hid.EnumerateOptions{Filter: hid.Filter{Bus: &bus, Usage: &usage}, ResolveStrings: true}
}

func isFIDOEndpoint(endpoint hid.Endpoint) bool {
	return endpoint.Bus == hid.BusUSB && endpoint.Usage.Known && endpoint.Usage.Value == (hid.Usage{Page: fidoUsagePage, ID: fidoUsage})
}

func endpointDescriptor(endpoint hid.Endpoint) transport.DeviceDescriptor {
	return transport.DeviceDescriptor{ID: string(endpoint.ID), Transport: transport.KindUSB, Path: endpoint.Path, VendorID: endpoint.VendorID.Value, ProductID: endpoint.ProductID.Value, Manufacturer: endpoint.Manufacturer.Value, Product: endpoint.Product.Value, SerialNumber: endpoint.Serial.Value}
}

func (backend *HIDBackend) inventory(ctx context.Context) (hid.Snapshot, error) {
	snapshot, err := backend.native().Enumerate(ctx, fidoOptions())
	if err != nil {
		return snapshot, err
	}
	if !snapshot.Complete {
		return snapshot, incompleteInventory(snapshot)
	}
	return snapshot, nil
}

func incompleteInventory(snapshot hid.Snapshot) error {
	return errors.Join(append([]error{errors.New("transport/usb: incomplete FIDO HID inventory")}, snapshot.Warnings...)...)
}

// Discover returns complete inventory of exact USB FIDO application usages.
// An incomplete snapshot is an error and cannot establish device removal.
func (backend *HIDBackend) Discover(ctx context.Context) ([]transport.DeviceDescriptor, error) {
	if ctx == nil {
		return nil, transport.Wrap("discover usb hid devices", hid.ErrInvalidArgument)
	}
	snapshot, err := backend.inventory(ctx)
	if err != nil {
		return nil, transport.Wrap("discover usb hid devices", classifyHIDError(err))
	}
	devices := make([]transport.DeviceDescriptor, 0, len(snapshot.Endpoints))
	for _, endpoint := range snapshot.Endpoints {
		if isFIDOEndpoint(endpoint) {
			devices = append(devices, endpointDescriptor(endpoint))
		}
	}
	return devices, nil
}

// Open resolves an exact endpoint ID in fresh inventory. A path-only legacy
// request is accepted only if it names one unique FIDO application collection.
func (backend *HIDBackend) Open(ctx context.Context, device transport.DeviceDescriptor) (transport.Session, error) {
	wrap := func(err error) (transport.Session, error) {
		return nil, transport.Wrap("open usb hid session", classifyHIDError(err))
	}
	if ctx == nil {
		return wrap(hid.ErrInvalidArgument)
	}
	if err := ctx.Err(); err != nil {
		return wrap(err)
	}
	if device.Transport != "" && device.Transport != transport.KindUnknown && device.Transport != transport.KindUSB {
		return wrap(hid.ErrUnsupported)
	}
	if device.ID == "" && device.Path == "" {
		return wrap(hid.ErrInvalidArgument)
	}
	// An incomplete snapshot still proves that the endpoints it lists exist.
	// It only fails to prove absence, so it cannot report ErrRemoved.
	snapshot, err := backend.native().Enumerate(ctx, fidoOptions())
	if err != nil {
		return wrap(err)
	}
	var selected hid.Endpoint
	count := 0
	for _, endpoint := range snapshot.Endpoints {
		if !isFIDOEndpoint(endpoint) {
			continue
		}
		match := device.ID != "" && endpoint.ID == hid.EndpointID(device.ID)
		if device.ID == "" {
			match = endpoint.Path == device.Path
		}
		if match {
			selected = endpoint
			count++
		}
	}
	if count == 0 {
		if !snapshot.Complete {
			return wrap(incompleteInventory(snapshot))
		}
		return wrap(hid.ErrRemoved)
	}
	// A path-only request in partial inventory may miss a second candidate.
	if device.ID == "" && !snapshot.Complete {
		return wrap(incompleteInventory(snapshot))
	}
	if count != 1 {
		return wrap(fmt.Errorf("transport/usb: ambiguous endpoint selection: %w", hid.ErrInvalidArgument))
	}
	if !descriptorMatches(device, selected) {
		return wrap(hid.ErrStaleEndpoint)
	}
	conn, err := backend.native().Open(ctx, selected)
	if err != nil {
		return wrap(err)
	}
	if conn == nil {
		return wrap(hid.ErrIO)
	}
	layout := conn.Layout()
	if layout.Input.Size != hidReportSize || layout.Output.Size != hidReportSize {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), hidCloseTimeout)
		defer cancel()
		return wrap(errors.Join(hid.ErrUnsupported, conn.Close(cleanupCtx)))
	}
	return &hidSession{device: endpointDescriptor(conn.Endpoint()), conn: conn, layout: layout, reportSize: hidReportSize}, nil
}

func descriptorMatches(expected transport.DeviceDescriptor, actual hid.Endpoint) bool {
	return (expected.Path == "" || expected.Path == actual.Path) &&
		(expected.VendorID == 0 || actual.VendorID.Known && expected.VendorID == actual.VendorID.Value) &&
		(expected.ProductID == 0 || actual.ProductID.Known && expected.ProductID == actual.ProductID.Value) &&
		(expected.SerialNumber == "" || actual.Serial.Known && expected.SerialNumber == actual.Serial.Value) &&
		(expected.Manufacturer == "" || actual.Manufacturer.Known && expected.Manufacturer == actual.Manufacturer.Value) &&
		(expected.Product == "" || actual.Product.Known && expected.Product == actual.Product.Value)
}

func classifyHIDError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, hid.ErrRemoved):
		return transport.Disconnected(err)
	case errors.Is(err, hid.ErrPermission):
		return transport.PermissionDenied(err)
	case errors.Is(err, hid.ErrUnsupported):
		return transport.Unsupported(err)
	default:
		return transport.ClassifyCommon(err)
	}
}
