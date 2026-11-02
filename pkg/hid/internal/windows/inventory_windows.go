//go:build windows

package windows

import (
	"errors"
	"strconv"
	"strings"
	"unsafe"

	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/driver"
	"golang.org/x/sys/windows"
)

// Enumerate lists native HID collection interfaces, preserving inaccessible ones.
func Enumerate(resolveStrings bool) (driver.Snapshot, error) {
	snapshot := driver.Snapshot{Complete: true}
	if err := hidDLL.Load(); err != nil {
		snapshot.Complete = false
		return snapshot, nativeError("load hid.dll", err)
	}
	var guid windows.GUID
	getHidGUID.Call(uintptr(unsafe.Pointer(&guid)))
	set, err := windows.SetupDiGetClassDevsEx(&guid, "", 0, windows.DIGCF_PRESENT|windows.DIGCF_DEVICEINTERFACE, 0, "")
	if err != nil {
		snapshot.Complete = false
		return snapshot, nativeError("SetupDiGetClassDevs", err)
	}
	defer windows.SetupDiDestroyDeviceInfoList(set)
	for index := uint32(0); ; index++ {
		data := interfaceData{Size: uint32(unsafe.Sizeof(interfaceData{}))}
		err = boolCall(enumInterfaces, uintptr(set), 0, uintptr(unsafe.Pointer(&guid)), uintptr(index), uintptr(unsafe.Pointer(&data)))
		if errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
			break
		}
		if err != nil {
			snapshot.Complete = false
			snapshot.Warnings = append(snapshot.Warnings, nativeError("SetupDiEnumDeviceInterfaces", err))
			break
		}
		if index >= driver.MaxInventoryDevices {
			snapshot.Complete = false
			snapshot.Warnings = append(snapshot.Warnings, resourceLimit("inventory device limit"))
			break
		}
		path, dev, detailErr := interfacePath(set, &data)
		if detailErr != nil {
			snapshot.Complete = false
			snapshot.Warnings = append(snapshot.Warnings, detailErr)
			continue
		}
		ep := driver.Endpoint{ID: endpointID(path), Path: path}
		metadataFromDevInfo(dev, &ep)
		handle, openErr := openPath(path, 0, false)
		if openErr != nil {
			snapshot.Complete = false
			snapshot.Warnings = append(snapshot.Warnings, openErr)
		} else {
			if metadataErr := metadataFromHandle(handle, &ep, resolveStrings); metadataErr != nil {
				snapshot.Complete = false
				snapshot.Warnings = append(snapshot.Warnings, metadataErr)
			}
			if closeErr := windows.CloseHandle(handle); closeErr != nil {
				snapshot.Warnings = append(snapshot.Warnings, nativeError("close inventory handle", closeErr))
			}
		}
		snapshot.Endpoints = append(snapshot.Endpoints, ep)
	}
	return snapshot, nil
}

func endpointID(path string) string { return "windows:" + path }

func interfacePath(set windows.DevInfo, data *interfaceData) (string, *windows.DevInfoData, error) {
	var required uint32
	err := boolCall(getInterfaceDetail, uintptr(set), uintptr(unsafe.Pointer(data)), 0, 0, uintptr(unsafe.Pointer(&required)), 0)
	if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
		if err == nil {
			err = windows.ERROR_INVALID_DATA
		}
		return "", nil, nativeError("size interface detail", err)
	}
	if required < 6 || required > driver.MaxMetadataSize || required%2 != 0 {
		return "", nil, unsupported("invalid device interface path size")
	}
	buffer := make([]uint16, required/2)
	size := uint32(6)
	if unsafe.Sizeof(uintptr(0)) == 8 {
		size = 8
	}
	*(*uint32)(unsafe.Pointer(&buffer[0])) = size
	dev := new(windows.DevInfoData)
	// x/sys deliberately keeps cbSize private; the native ABI always places it
	// first, and this buffer is passed directly to SetupAPI.
	*(*uint32)(unsafe.Pointer(dev)) = uint32(unsafe.Sizeof(*dev))
	err = boolCall(getInterfaceDetail, uintptr(set), uintptr(unsafe.Pointer(data)), uintptr(unsafe.Pointer(&buffer[0])), uintptr(required), uintptr(unsafe.Pointer(&required)), uintptr(unsafe.Pointer(dev)))
	if err != nil {
		return "", nil, nativeError("SetupDiGetDeviceInterfaceDetail", err)
	}
	if required > uint32(len(buffer)*2) {
		return "", nil, unsupported("device interface path grew during enumeration")
	}
	for i := 2; i < len(buffer); i++ {
		if buffer[i] == 0 {
			if i == 2 {
				return "", nil, unsupported("empty device interface path")
			}
			return windows.UTF16ToString(buffer[2:i]), dev, nil
		}
	}
	return "", nil, unsupported("unterminated device interface path")
}

func metadataFromHandle(handle windows.Handle, ep *driver.Endpoint, resolveStrings bool) error {
	var failures []error
	attrs := attributes{Size: uint32(unsafe.Sizeof(attributes{}))}
	if err := boolCall(getAttributes, uintptr(handle), uintptr(unsafe.Pointer(&attrs))); err != nil {
		failures = append(failures, nativeError("HidD_GetAttributes", err))
	} else {
		ep.VendorID = driver.Field[uint16]{Value: attrs.VendorID, Known: true}
		ep.ProductID = driver.Field[uint16]{Value: attrs.ProductID, Known: true}
	}
	caps, preparsed, err := readCaps(handle)
	if err != nil {
		failures = append(failures, err)
	} else {
		ep.Usage = driver.Field[driver.Usage]{Value: driver.Usage{Page: caps.UsagePage, ID: caps.Usage}, Known: true}
		freePreparsedData.Call(preparsed)
	}
	if resolveStrings {
		ep.Serial = stringProperty(handle, getSerial)
		ep.Manufacturer = stringProperty(handle, getManufacturer)
		ep.Product = stringProperty(handle, getProduct)
	}
	return errors.Join(failures...)
}

func metadataFromDevInfo(dev *windows.DevInfoData, ep *driver.Endpoint) {
	// Native instance IDs are bounded OS metadata available even when access
	// to the collection is restricted. No serial is inferred from an ID.
	instance := uint32(dev.DevInst)
	for depth := 0; depth < 16; depth++ {
		var buffer [512]uint16
		status, _, _ := getDeviceID.Call(uintptr(instance), uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)), 0)
		if status == 0 {
			terminated := false
			for _, c := range buffer {
				if c == 0 {
					terminated = true
					break
				}
			}
			if terminated {
				id := windows.UTF16ToString(buffer[:])
				hardwareFields(id, ep)
				upper := strings.ToUpper(id)
				if ep.Bus == driver.BusUnknown {
					switch {
					case strings.HasPrefix(upper, "USB\\"):
						ep.Bus = driver.BusUSB
					case strings.HasPrefix(upper, "BTHENUM\\"), strings.HasPrefix(upper, "BTHLEDEVICE\\"):
						ep.Bus = driver.BusBluetooth
					}
				}
			}
		}
		var parent uint32
		status, _, _ = getParent.Call(uintptr(unsafe.Pointer(&parent)), uintptr(instance), 0)
		if status != 0 || parent == instance {
			break
		}
		instance = parent
	}
}

func resourceLimit(message string) error {
	return &driver.Error{Op: "enumerate", Kind: driver.KindResourceLimit, Message: message}
}

func findInterface(path string) (driver.Endpoint, error) {
	var guid windows.GUID
	getHidGUID.Call(uintptr(unsafe.Pointer(&guid)))
	set, err := windows.SetupDiGetClassDevsEx(&guid, "", 0, windows.DIGCF_PRESENT|windows.DIGCF_DEVICEINTERFACE, 0, "")
	if err != nil {
		return driver.Endpoint{}, nativeError("SetupDiGetClassDevs", err)
	}
	defer windows.SetupDiDestroyDeviceInfoList(set)
	var failures []error
	for index := uint32(0); ; index++ {
		data := interfaceData{Size: uint32(unsafe.Sizeof(interfaceData{}))}
		err = boolCall(enumInterfaces, uintptr(set), 0, uintptr(unsafe.Pointer(&guid)), uintptr(index), uintptr(unsafe.Pointer(&data)))
		if errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
			if len(failures) > 0 {
				return driver.Endpoint{}, &driver.Error{Op: "open", Kind: driver.KindIO, Message: "incomplete native address lookup", Cause: errors.Join(failures...)}
			}
			return driver.Endpoint{}, nativeError("open", windows.ERROR_DEVICE_NOT_CONNECTED)
		}
		if err != nil {
			return driver.Endpoint{}, nativeError("SetupDiEnumDeviceInterfaces", err)
		}
		if index >= driver.MaxInventoryDevices {
			return driver.Endpoint{}, resourceLimit("inventory device limit")
		}
		candidate, dev, err := interfacePath(set, &data)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if candidate != path {
			continue
		}
		ep := driver.Endpoint{ID: endpointID(path), Path: path}
		metadataFromDevInfo(dev, &ep)
		return ep, nil
	}
}

func hardwareFields(id string, ep *driver.Endpoint) {
	upper := strings.ToUpper(id)
	for _, property := range []struct {
		tag    string
		target *driver.Field[uint16]
	}{{"VID_", &ep.VendorID}, {"PID_", &ep.ProductID}} {
		if property.target.Known {
			continue
		}
		at := strings.Index(upper, property.tag)
		if at >= 0 && at+8 <= len(upper) {
			if value, err := strconv.ParseUint(upper[at+4:at+8], 16, 16); err == nil {
				*property.target = driver.Field[uint16]{Value: uint16(value), Known: true}
			}
		}
	}
	if !ep.Interface.Known {
		at := strings.Index(upper, "&MI_")
		if at >= 0 && at+6 <= len(upper) {
			if value, err := strconv.ParseUint(upper[at+4:at+6], 16, 8); err == nil {
				ep.Interface = driver.Field[int]{Value: int(value), Known: true}
			}
		}
	}
}
