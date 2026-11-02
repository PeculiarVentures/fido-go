//go:build windows

// Package windows implements HID access using SetupAPI, HIDClass and Win32.
package windows

import (
	"errors"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/driver"
	"golang.org/x/sys/windows"
)

var (
	hidDLL             = windows.NewLazySystemDLL("hid.dll")
	getHidGUID         = hidDLL.NewProc("HidD_GetHidGuid")
	getAttributes      = hidDLL.NewProc("HidD_GetAttributes")
	getPreparsedData   = hidDLL.NewProc("HidD_GetPreparsedData")
	freePreparsedData  = hidDLL.NewProc("HidD_FreePreparsedData")
	getCaps            = hidDLL.NewProc("HidP_GetCaps")
	initializeReport   = hidDLL.NewProc("HidP_InitializeReportForID")
	getSerial          = hidDLL.NewProc("HidD_GetSerialNumberString")
	getManufacturer    = hidDLL.NewProc("HidD_GetManufacturerString")
	getProduct         = hidDLL.NewProc("HidD_GetProductString")
	setupDLL           = windows.NewLazySystemDLL("setupapi.dll")
	enumInterfaces     = setupDLL.NewProc("SetupDiEnumDeviceInterfaces")
	getInterfaceDetail = setupDLL.NewProc("SetupDiGetDeviceInterfaceDetailW")
	configDLL          = windows.NewLazySystemDLL("cfgmgr32.dll")
	getParent          = configDLL.NewProc("CM_Get_Parent")
	getDeviceID        = configDLL.NewProc("CM_Get_Device_IDW")
)

const (
	hidpSuccess            = 0x00110000
	hidpReportDoesNotExist = 0xc0110010
)

type attributes struct {
	Size                               uint32
	VendorID, ProductID, VersionNumber uint16
}
type capabilities struct {
	Usage, UsagePage                                                                                                                     uint16
	InputLength, OutputLength, FeatureLength                                                                                             uint16
	Reserved                                                                                                                             [17]uint16
	LinkNodes, InputButtons, InputValues, InputData, OutputButtons, OutputValues, OutputData, FeatureButtons, FeatureValues, FeatureData uint16
}
type interfaceData struct {
	Size     uint32
	GUID     windows.GUID
	Flags    uint32
	Reserved uintptr
}

func boolCall(proc *windows.LazyProc, args ...uintptr) error {
	result, _, err := proc.Call(args...)
	// HidD routines return BOOLEAN, whereas SetupAPI returns the wider BOOL.
	if proc == getAttributes || proc == getPreparsedData || proc == getSerial || proc == getManufacturer || proc == getProduct {
		result &= 0xff
	}
	if result != 0 {
		return nil
	}
	if err == syscall.Errno(0) {
		return windows.ERROR_GEN_FAILURE
	}
	return err
}

func nativeError(op string, err error) error {
	kind := driver.KindIO
	switch {
	case errors.Is(err, windows.ERROR_ACCESS_DENIED), errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD):
		kind = driver.KindPermission
	case errors.Is(err, windows.ERROR_DEVICE_NOT_CONNECTED), errors.Is(err, windows.ERROR_NO_SUCH_DEVICE), errors.Is(err, windows.ERROR_FILE_NOT_FOUND), errors.Is(err, windows.ERROR_PATH_NOT_FOUND):
		kind = driver.KindRemoved
	case errors.Is(err, windows.ERROR_SHARING_VIOLATION), errors.Is(err, windows.ERROR_BUSY):
		kind = driver.KindBusy
	}
	var code syscall.Errno
	errors.As(err, &code)
	return &driver.Error{Op: op, Kind: kind, Domain: "win32", Code: uint64(code), Cause: err}
}
func unsupported(message string) error {
	return &driver.Error{Op: "qualify", Kind: driver.KindUnsupported, Message: message}
}
func stale(message string) error {
	return &driver.Error{Op: "open", Kind: driver.KindStaleEndpoint, Message: message}
}
func hidpError(op string, status uintptr) error {
	return &driver.Error{Op: op, Kind: driver.KindUnsupported, Domain: "hidp", Code: uint64(uint32(status)), Message: "HID parser rejected capabilities"}
}

func readCaps(handle windows.Handle) (capabilities, uintptr, error) {
	var caps capabilities
	var preparsed uintptr
	if err := boolCall(getPreparsedData, uintptr(handle), uintptr(unsafe.Pointer(&preparsed))); err != nil {
		return caps, 0, nativeError("HidD_GetPreparsedData", err)
	}
	status, _, _ := getCaps.Call(preparsed, uintptr(unsafe.Pointer(&caps)))
	if uint32(status) != hidpSuccess {
		freePreparsedData.Call(preparsed)
		return caps, 0, hidpError("HidP_GetCaps", status)
	}
	return caps, preparsed, nil
}

func reportSpec(preparsed uintptr, reportType uintptr, length uint16) (driver.ReportSpec, error) {
	if length < 2 || int(length)-1 > driver.MaxReportSize {
		return driver.ReportSpec{}, unsupported("missing or oversized Input/Output report")
	}
	buffer := make([]byte, int(length))
	var spec driver.ReportSpec
	count := 0
	// Probe every possible ID using the documented HID parser API, including
	// ID zero. Once there is exactly one report, the caps maximum is its exact
	// length. Multiple IDs are rejected rather than assigning that maximum to
	// shorter reports or relying on incomplete value/button capability arrays.
	for id := 0; id < 256; id++ {
		status, _, _ := initializeReport.Call(reportType, uintptr(id), preparsed, uintptr(unsafe.Pointer(&buffer[0])), uintptr(length))
		switch uint32(status) {
		case hidpSuccess:
			count++
			spec = driver.ReportSpec{ID: uint8(id), Size: int(length) - 1}
		case hidpReportDoesNotExist:
		default:
			return driver.ReportSpec{}, hidpError("HidP_InitializeReportForID", status)
		}
	}
	runtime.KeepAlive(buffer)
	if count != 1 {
		return driver.ReportSpec{}, unsupported("collection does not have exactly one report ID per direction")
	}
	return spec, nil
}

func stringProperty(handle windows.Handle, proc *windows.LazyProc) driver.Field[string] {
	// HID strings are limited to 126 UTF-16 code units on USB. Keep the native
	// byte count below 4093, and require a terminator inside our owned buffer.
	var buffer [256]uint16
	if err := boolCall(proc, uintptr(handle), uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Sizeof(buffer))); err != nil {
		return driver.Field[string]{}
	}
	for i, c := range buffer {
		if c == 0 {
			return driver.Field[string]{Value: windows.UTF16ToString(buffer[:i]), Known: true}
		}
	}
	return driver.Field[string]{}
}

func openPath(path string, access uint32, overlapped bool) (windows.Handle, error) {
	wide, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, &driver.Error{Op: "open", Kind: driver.KindInvalidArgument, Cause: err}
	}
	flags := uint32(0)
	if overlapped {
		flags = windows.FILE_FLAG_OVERLAPPED
	}
	handle, err := windows.CreateFile(wide, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, flags, 0)
	if err != nil {
		return windows.InvalidHandle, nativeError("CreateFile", err)
	}
	return handle, nil
}
