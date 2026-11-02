//go:build windows

package windows

import (
	"errors"
	"runtime"
	"strings"
	"time"

	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/driver"
	"golang.org/x/sys/windows"
)

type device struct {
	handle   windows.Handle
	endpoint driver.Endpoint
	layout   driver.Layout
}

type openSystem struct {
	find     func(string) (driver.Endpoint, error)
	open     func(string) (windows.Handle, error)
	close    func(windows.Handle) error
	metadata func(windows.Handle, *driver.Endpoint, bool) error
	layout   func(windows.Handle) (driver.Layout, error)
}

var nativeOpenSystem = openSystem{
	find: findInterface,
	open: func(path string) (windows.Handle, error) {
		return openPath(path, windows.GENERIC_READ|windows.GENERIC_WRITE, true)
	},
	close: windows.CloseHandle, metadata: metadataFromHandle, layout: readLayout,
}

// Open opens exactly the selected native collection interface.
func Open(expected driver.Endpoint) (driver.Device, error) {
	if err := hidDLL.Load(); err != nil {
		return nil, nativeError("load hid.dll", err)
	}
	return openWithSystem(expected, nativeOpenSystem)
}

func openWithSystem(expected driver.Endpoint, system openSystem) (driver.Device, error) {
	path, ok := strings.CutPrefix(expected.ID, "windows:")
	if !ok || path == "" || len(path) > driver.MaxMetadataSize || strings.IndexByte(path, 0) >= 0 || endpointID(path) != expected.ID {
		return nil, &driver.Error{Op: "open", Kind: driver.KindInvalidArgument, Message: "invalid Windows endpoint ID"}
	}
	if expected.Path != "" && expected.Path != path {
		return nil, stale("diagnostic path differs from endpoint ID")
	}
	// Refresh address metadata without accepting a neighbouring VID/PID match.
	actual, err := system.find(path)
	if err != nil {
		return nil, err
	}
	handle, err := system.open(path)
	if err != nil {
		return nil, err
	}
	failed := true
	defer func() {
		if failed {
			system.close(handle)
		}
	}()
	if err = system.metadata(handle, &actual, true); err != nil {
		return nil, err
	}
	if !matches(expected, actual) {
		return nil, stale("opened metadata differs from requested endpoint")
	}
	layout, err := system.layout(handle)
	if err != nil {
		return nil, err
	}
	failed = false
	return &device{handle: handle, endpoint: actual, layout: layout}, nil
}

func readLayout(handle windows.Handle) (driver.Layout, error) {
	caps, preparsed, err := readCaps(handle)
	if err != nil {
		return driver.Layout{}, err
	}
	defer freePreparsedData.Call(preparsed)
	input, err := reportSpec(preparsed, 0, caps.InputLength)
	if err != nil {
		return driver.Layout{}, err
	}
	output, err := reportSpec(preparsed, 1, caps.OutputLength)
	if err != nil {
		return driver.Layout{}, err
	}
	return driver.Layout{Input: input, Output: output}, nil
}

func matches(want, got driver.Endpoint) bool {
	return (!want.VendorID.Known || got.VendorID == want.VendorID) && (!want.ProductID.Known || got.ProductID == want.ProductID) && (!want.Usage.Known || got.Usage == want.Usage) && (!want.Interface.Known || got.Interface == want.Interface) && (want.Bus == driver.BusUnknown || got.Bus == want.Bus) && (!want.Serial.Known || got.Serial == want.Serial) && (!want.Manufacturer.Known || got.Manufacturer == want.Manufacturer) && (!want.Product.Known || got.Product == want.Product)
}

// Endpoint returns metadata checked against the open handle.
func (d *device) Endpoint() driver.Endpoint { return d.endpoint }

// Layout returns the single report format accepted for each direction.
func (d *device) Layout() driver.Layout { return d.layout }

// Read waits for one report and joins any canceled request before returning.
func (d *device) Read(wait time.Duration) (driver.Report, error) {
	if wait < 0 {
		return driver.Report{}, &driver.Error{Op: "read", Kind: driver.KindInvalidArgument}
	}
	buffer := make([]byte, d.layout.Input.Size+2)
	n, _, err := d.transfer(buffer, false, wait)
	if err != nil {
		return driver.Report{}, err
	}
	if n != uint32(d.layout.Input.Size+1) || buffer[0] != d.layout.Input.ID {
		return driver.Report{}, &driver.Error{Op: "read", Kind: driver.KindInvalidReport, Message: "native input ID or size differs from capabilities"}
	}
	return driver.Report{ID: buffer[0], Data: append([]byte(nil), buffer[1:n]...)}, nil
}

// Write owns a native buffer until overlapped completion is established.
func (d *device) Write(report driver.Report) (driver.WriteResult, error) {
	if report.ID != d.layout.Output.ID || len(report.Data) != d.layout.Output.Size {
		return driver.WriteResult{Outcome: driver.OutcomeNotSubmitted}, &driver.Error{Op: "write", Kind: driver.KindInvalidReport}
	}
	buffer := make([]byte, len(report.Data)+1)
	buffer[0] = report.ID
	copy(buffer[1:], report.Data)
	n, submitted, err := d.transfer(buffer, true, 0)
	if !submitted {
		return driver.WriteResult{Outcome: driver.OutcomeNotSubmitted}, err
	}
	if n == uint32(len(buffer)) {
		return driver.WriteResult{Outcome: driver.OutcomeCompleted}, err
	}
	if err == nil {
		err = &driver.Error{Op: "write", Kind: driver.KindIO, Message: "short native write"}
	}
	return driver.WriteResult{Outcome: driver.OutcomeUnknown}, err
}

func (d *device) transfer(buffer []byte, write bool, wait time.Duration) (done uint32, submitted bool, result error) {
	op := "read"
	if write {
		op = "write"
	}
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return 0, false, nativeError("CreateEvent", err)
	}
	defer func() {
		if err := windows.CloseHandle(event); err != nil {
			result = errors.Join(result, nativeError("close I/O event", err))
		}
	}()
	overlapped := &windows.Overlapped{HEvent: event}
	var pinned runtime.Pinner
	pinned.Pin(&buffer[0])
	pinned.Pin(overlapped)
	defer pinned.Unpin()
	if write {
		err = windows.WriteFile(d.handle, buffer, &done, overlapped)
	} else {
		err = windows.ReadFile(d.handle, buffer, &done, overlapped)
	}
	// Even immediate completion has entered the native I/O path. Only event
	// creation is definitely pre-submission; Win32 failure is conservative.
	submitted = true
	if err != nil && !errors.Is(err, windows.ERROR_IO_PENDING) {
		return 0, true, nativeError(op, err)
	}
	if err == nil {
		// The completion API is authoritative even when the overlapped call
		// completes inline; lpNumberOfBytesRead/Written is not relied upon.
		err = windows.GetOverlappedResult(d.handle, overlapped, &done, true)
		runtime.KeepAlive(buffer)
		if err != nil {
			return 0, true, nativeError(op, err)
		}
		return done, true, nil
	}
	timeout := uint32(windows.INFINITE)
	if wait > 0 {
		milliseconds := wait / time.Millisecond
		if wait%time.Millisecond != 0 {
			milliseconds++
		}
		if milliseconds >= time.Duration(windows.INFINITE) {
			milliseconds = time.Duration(windows.INFINITE - 1)
		}
		timeout = uint32(milliseconds)
	}
	state, waitErr := windows.WaitForSingleObject(event, timeout)
	timedOut := waitErr == nil && state == uint32(windows.WAIT_TIMEOUT)
	var cancellationErr error
	if waitErr != nil || timedOut {
		cancellationErr = windows.CancelIoEx(d.handle, overlapped)
		if errors.Is(cancellationErr, windows.ERROR_NOT_FOUND) {
			cancellationErr = nil
		}
	}
	// CancelIoEx requests cancellation only. The blocking completion join owns
	// the pinned buffer, OVERLAPPED and event until the driver stops using them.
	err = windows.GetOverlappedResult(d.handle, overlapped, &done, true)
	runtime.KeepAlive(buffer)
	runtime.KeepAlive(overlapped)
	if err == nil {
		if waitErr != nil {
			return done, true, nativeError("wait completion", waitErr)
		}
		if cancellationErr != nil {
			return done, true, nativeError("CancelIoEx", cancellationErr)
		}
		return done, true, nil
	}
	if timedOut && errors.Is(err, windows.ERROR_OPERATION_ABORTED) {
		return 0, true, &driver.Error{Op: op, Kind: driver.KindTimeout, Domain: "win32", Code: uint64(windows.ERROR_OPERATION_ABORTED), Cause: errors.Join(err, cancellationErr)}
	}
	return 0, true, nativeError(op, errors.Join(err, waitErr, cancellationErr))
}

// Close releases the handle only after all native operations have returned.
func (d *device) Close() error {
	if err := windows.CloseHandle(d.handle); err != nil {
		return nativeError("CloseHandle", err)
	}
	return nil
}
