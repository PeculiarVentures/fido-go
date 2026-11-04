//go:build linux

// Package linux implements native HID inventory and hidraw report I/O.
package linux

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/driver"
	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/reportdesc"
	"golang.org/x/sys/unix"
)

const classPath = "/sys/class/hidraw"

type inventoryEntry struct {
	endpoint   driver.Endpoint
	sysPath    string
	dev        uint64
	descriptor []byte
	hidUnique  driver.Field[string]
}

// Enumerate preserves each Application collection as a separate endpoint.
func Enumerate(resolveStrings bool) (driver.Snapshot, error) {
	snapshot := driver.Snapshot{Complete: true}
	directory, err := os.Open(classPath)
	if errors.Is(err, os.ErrNotExist) {
		return snapshot, nil
	}
	if err != nil {
		snapshot.Complete = false
		return snapshot, nativeError("enumerate", err)
	}
	defer directory.Close()
	entries, err := directory.ReadDir(driver.MaxInventoryDevices + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		snapshot.Complete = false
		return snapshot, nativeError("enumerate entries", err)
	}
	if len(entries) > driver.MaxInventoryDevices {
		entries = entries[:driver.MaxInventoryDevices]
		snapshot.Complete = false
		snapshot.Warnings = append(snapshot.Warnings, resourceLimit("inventory device limit"))
	}
	for _, entry := range entries {
		if len(snapshot.Endpoints) >= driver.MaxInventoryEndpoints {
			snapshot.Complete = false
			snapshot.Warnings = append(snapshot.Warnings, resourceLimit("inventory endpoint limit"))
			return snapshot, nil
		}
		item, itemErr := inspect(filepath.Join(classPath, entry.Name()), resolveStrings)
		if itemErr != nil {
			snapshot.Complete = false
			snapshot.Warnings = append(snapshot.Warnings, itemErr)
		}
		if item.sysPath == "" {
			continue
		}
		desc, parseErr := reportdesc.Inventory(item.descriptor)
		if parseErr != nil && len(desc.Collections) != 0 {
			// Usages are known; only I/O layout is unsupported. This is not an
			// inventory omission, and Open rejects the collection itself.
			snapshot.Warnings = append(snapshot.Warnings, parseErr)
		} else if parseErr != nil || len(desc.Collections) == 0 {
			snapshot.Complete = false
			if parseErr == nil {
				parseErr = unsupported("descriptor has no addressable Application collection")
			}
			snapshot.Warnings = append(snapshot.Warnings, parseErr)
			item.endpoint.ID = endpointID(item.sysPath, -1)
			snapshot.Endpoints = append(snapshot.Endpoints, item.endpoint)
			continue
		}
		for _, collection := range desc.Collections {
			if len(snapshot.Endpoints) == driver.MaxInventoryEndpoints {
				snapshot.Complete = false
				snapshot.Warnings = append(snapshot.Warnings, resourceLimit("inventory endpoint limit"))
				return snapshot, nil
			}
			ep := item.endpoint
			ep.ID = endpointID(item.sysPath, collection.Index)
			ep.Usage = driver.Field[driver.Usage]{Value: collection.Usage, Known: true}
			snapshot.Endpoints = append(snapshot.Endpoints, ep)
		}
	}
	return snapshot, nil
}

func endpointID(path string, collection int) string {
	return "linux:" + path + "#collection=" + strconv.Itoa(collection)
}

func inspect(path string, resolveStrings bool) (inventoryEntry, error) {
	var item inventoryEntry
	realPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		return item, nativeError("resolve sysfs endpoint", err)
	}
	item.sysPath = realPath
	if len(realPath) > driver.MaxMetadataSize {
		return inventoryEntry{}, resourceLimit("sysfs path length")
	}
	var failures []error
	devText, err := readText(filepath.Join(path, "dev"))
	if err != nil {
		failures = append(failures, nativeError("read device number", err))
	} else {
		parts := strings.Split(devText, ":")
		if len(parts) != 2 {
			failures = append(failures, unsupported("invalid sysfs device number"))
		} else {
			major, e1 := strconv.ParseUint(parts[0], 10, 32)
			minor, e2 := strconv.ParseUint(parts[1], 10, 32)
			if e1 != nil || e2 != nil {
				failures = append(failures, unsupported("invalid sysfs device number"))
			} else {
				item.dev = unix.Mkdev(uint32(major), uint32(minor))
			}
		}
	}
	uevent, err := readProperties(filepath.Join(path, "uevent"))
	if err != nil {
		failures = append(failures, nativeError("read hidraw uevent", err))
	}
	name := uevent["DEVNAME"]
	if name == "" {
		name = filepath.Base(path)
	}
	item.endpoint.Path = filepath.Join("/dev", name)
	if !strings.HasPrefix(item.endpoint.Path, "/dev/") || len(item.endpoint.Path) > driver.MaxMetadataSize {
		failures = append(failures, unsupported("invalid hidraw device path"))
		item.endpoint.Path = ""
	}
	if item.endpoint.Path != "" {
		item.endpoint.Path, err = resolveNode(item.endpoint.Path, item.dev)
		if err != nil {
			failures = append(failures, err)
		}
	}
	hidPath := filepath.Join(path, "device")
	hid, err := readProperties(filepath.Join(hidPath, "uevent"))
	if err != nil {
		failures = append(failures, nativeError("read HID metadata", err))
	}
	parts := strings.Split(hid["HID_ID"], ":")
	if len(parts) == 3 {
		bus, e1 := strconv.ParseUint(parts[0], 16, 16)
		vendor, e2 := strconv.ParseUint(parts[1], 16, 32)
		product, e3 := strconv.ParseUint(parts[2], 16, 32)
		if e1 == nil && e2 == nil && e3 == nil && vendor <= 0xffff && product <= 0xffff {
			item.endpoint.Bus = busType(uint32(bus))
			item.endpoint.VendorID = driver.Field[uint16]{Value: uint16(vendor), Known: true}
			item.endpoint.ProductID = driver.Field[uint16]{Value: uint16(product), Known: true}
		} else {
			failures = append(failures, unsupported("invalid HID_ID"))
		}
	} else {
		failures = append(failures, unsupported("missing HID_ID"))
	}
	if resolveStrings {
		if value, ok := hid["HID_UNIQ"]; ok {
			item.endpoint.Serial = driver.Field[string]{Value: value, Known: true}
		}
		if value, ok := hid["HID_NAME"]; ok {
			item.endpoint.Product = driver.Field[string]{Value: value, Known: true}
		}
	}
	if value, ok := hid["HID_UNIQ"]; ok {
		item.hidUnique = driver.Field[string]{Value: value, Known: true}
	}
	parent, _ := filepath.EvalSymlinks(hidPath)
	readUSBMetadata(parent, &item.endpoint, resolveStrings)
	item.descriptor, err = readBounded(filepath.Join(hidPath, "report_descriptor"), driver.MaxDescriptorSize)
	if err != nil {
		failures = append(failures, nativeError("read report descriptor", err))
	}
	return item, errors.Join(failures...)
}

func readUSBMetadata(parent string, endpoint *driver.Endpoint, resolveStrings bool) {
	if endpoint.Bus != driver.BusUSB {
		return
	}
	// Interface attributes precede the nearest USB device in the sysfs chain.
	// Stop at that device even when its optional strings are unavailable: the
	// next USB ancestor describes a hub, not this HID endpoint.
	for depth := 0; parent != "" && parent != "/" && depth < 16; depth++ {
		_, vendorErr := os.Stat(filepath.Join(parent, "idVendor"))
		_, productErr := os.Stat(filepath.Join(parent, "idProduct"))
		if vendorErr == nil && productErr == nil {
			if resolveStrings {
				for _, property := range []struct {
					name   string
					target *driver.Field[string]
				}{{"manufacturer", &endpoint.Manufacturer}, {"product", &endpoint.Product}, {"serial", &endpoint.Serial}} {
					if value, err := readText(filepath.Join(parent, property.name)); err == nil {
						*property.target = driver.Field[string]{Value: value, Known: true}
					}
				}
			}
			return
		}
		if !endpoint.Interface.Known {
			if value, e := readText(filepath.Join(parent, "bInterfaceNumber")); e == nil {
				if number, e := strconv.ParseUint(value, 16, 8); e == nil {
					endpoint.Interface = driver.Field[int]{Value: int(number), Known: true}
				}
			}
		}
		parent = filepath.Dir(parent)
	}
}

func resolveNode(path string, deviceNumber uint64) (string, error) {
	var stat unix.Stat_t
	err := unix.Stat(path, &stat)
	if err == nil {
		if stat.Mode&unix.S_IFMT != unix.S_IFCHR || stat.Rdev != deviceNumber {
			return path, stale("hidraw node does not match sysfs device number")
		}
		return path, nil
	}
	if !errors.Is(err, unix.ENOENT) {
		return path, nativeError("resolve hidraw node", err)
	}
	// udev commonly supplies a device-number link even when the usual node
	// name differs. Resolve that link, then verify its character device number.
	alias := filepath.Join("/dev/char", fmt.Sprintf("%d:%d", unix.Major(deviceNumber), unix.Minor(deviceNumber)))
	resolved, aliasErr := filepath.EvalSymlinks(alias)
	if aliasErr == nil && len(resolved) <= driver.MaxMetadataSize {
		if statErr := unix.Stat(resolved, &stat); statErr == nil && stat.Mode&unix.S_IFMT == unix.S_IFCHR && stat.Rdev == deviceNumber {
			return resolved, nil
		}
	}
	return path, nativeError("resolve hidraw node", err)
}

func readBounded(path string, limit int) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > limit {
		return nil, fmt.Errorf("sysfs property exceeds %d bytes", limit)
	}
	return data, nil
}

func readText(path string) (string, error) {
	data, err := readBounded(path, driver.MaxMetadataSize)
	return strings.TrimSuffix(string(data), "\n"), err
}
func readProperties(path string) (map[string]string, error) {
	data, err := readBounded(path, 16384)
	if err != nil {
		return nil, err
	}
	result := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok {
			if len(key) > driver.MaxMetadataSize || len(value) > driver.MaxMetadataSize {
				return nil, resourceLimit("sysfs metadata length")
			}
			result[key] = value
		}
	}
	return result, nil
}
func busType(bus uint32) driver.Bus {
	switch bus {
	case 3:
		return driver.BusUSB
	case 5:
		return driver.BusBluetooth
	case 0x18:
		return driver.BusI2C
	case 0x1c:
		return driver.BusSPI
	case 0:
		return driver.BusUnknown
	default:
		return driver.BusOther
	}
}
func unsupported(message string) error {
	return &driver.Error{Op: "qualify", Kind: driver.KindUnsupported, Message: message}
}
func resourceLimit(message string) error {
	return &driver.Error{Op: "enumerate", Kind: driver.KindResourceLimit, Message: message}
}
func stale(message string) error {
	return &driver.Error{Op: "open", Kind: driver.KindStaleEndpoint, Message: message}
}
func nativeError(op string, err error) error {
	kind := driver.KindIO
	switch {
	case errors.Is(err, unix.EACCES), errors.Is(err, unix.EPERM):
		kind = driver.KindPermission
	case errors.Is(err, unix.ENODEV), errors.Is(err, unix.ENXIO), errors.Is(err, unix.ENOENT):
		kind = driver.KindRemoved
	case errors.Is(err, unix.EBUSY):
		kind = driver.KindBusy
	}
	var errno unix.Errno
	errors.As(err, &errno)
	return &driver.Error{Op: op, Kind: kind, Domain: "errno", Code: uint64(errno), Cause: err}
}
