//go:build linux

package linux

import (
	"bytes"
	"errors"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"unsafe"

	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/driver"
	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/reportdesc"
	"golang.org/x/sys/unix"
)

type sysfsAnchor struct {
	fd   int
	path string
	stat unix.Stat_t
}

// openSystem keeps the open transaction injectable without global test hooks.
type openSystem struct {
	anchor     func(string) (sysfsAnchor, error)
	verify     func(string, sysfsAnchor, inventoryEntry) error
	inspect    func(string, bool) (inventoryEntry, error)
	open       func(string) (int, error)
	close      func(int) error
	fstat      func(int, *unix.Stat_t) error
	info       func(int) (*unix.HIDRawDevInfo, error)
	descriptor func(int) ([]byte, error)
	unique     func(int) (string, error)
}

var nativeOpenSystem = openSystem{
	anchor: anchorSysfs, verify: verifySysfs, inspect: inspect,
	open:  func(path string) (int, error) { return unix.Open(path, unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0) },
	close: unix.Close, fstat: unix.Fstat, info: unix.IoctlHIDGetRawInfo,
	descriptor: readDescriptor, unique: readUnique,
}

// Open pins and revalidates the sysfs association throughout the fd open.
func Open(expected driver.Endpoint) (driver.Device, error) {
	return openWithSystem(expected, nativeOpenSystem)
}

func openWithSystem(expected driver.Endpoint, system openSystem) (driver.Device, error) {
	address, selector, ok := strings.Cut(strings.TrimPrefix(expected.ID, "linux:"), "#collection=")
	index, err := strconv.Atoi(selector)
	if len(expected.ID) > driver.MaxMetadataSize+64 || len(expected.Path) > driver.MaxMetadataSize || !strings.HasPrefix(expected.ID, "linux:/sys/") || !ok || err != nil || index < 0 || endpointID(address, index) != expected.ID {
		return nil, &driver.Error{Op: "open", Kind: driver.KindInvalidArgument, Message: "invalid Linux endpoint ID"}
	}
	path := filepath.Join(classPath, filepath.Base(address))
	anchor, err := system.anchor(path)
	if err != nil {
		return nil, err
	}
	defer system.close(anchor.fd)
	item, err := system.inspect(path, true)
	if err != nil {
		return nil, err
	}
	if item.sysPath != address || expected.Path != "" && expected.Path != item.endpoint.Path {
		return nil, stale("endpoint address changed")
	}
	if err = system.verify(path, anchor, item); err != nil {
		return nil, err
	}
	fd, err := system.open(item.endpoint.Path)
	if err != nil {
		return nil, nativeError("open", err)
	}
	failed := true
	defer func() {
		if failed {
			system.close(fd)
		}
	}()
	var stat unix.Stat_t
	if err = system.fstat(fd, &stat); err != nil {
		return nil, nativeError("fstat", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFCHR || stat.Rdev != item.dev {
		return nil, stale("opened node changed")
	}
	// A reused hidraw minor can have the same rdev. Refresh metadata only
	// while it is associated with the original, still-pinned sysfs inode.
	current, err := system.inspect(path, true)
	if err != nil {
		return nil, &driver.Error{Op: "open", Kind: driver.KindStaleEndpoint, Message: "sysfs endpoint changed while opening", Cause: err}
	}
	if current.sysPath != address || current.dev != stat.Rdev || current.endpoint.Path != item.endpoint.Path {
		return nil, stale("hidraw address was reused while opening")
	}
	if err = system.verify(path, anchor, current); err != nil {
		return nil, err
	}
	info, err := system.info(fd)
	if err != nil {
		return nil, nativeError("HIDIOCGRAWINFO", err)
	}
	if current.endpoint.Bus != busType(info.Bustype) || current.endpoint.VendorID.Value != uint16(info.Vendor) || current.endpoint.ProductID.Value != uint16(info.Product) {
		return nil, stale("opened fd differs from its sysfs association")
	}
	descriptor, err := system.descriptor(fd)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(descriptor, current.descriptor) {
		return nil, stale("opened fd report descriptor differs from sysfs")
	}
	unique, err := system.unique(fd)
	if err != nil && !errors.Is(err, unix.ENOTTY) && !errors.Is(err, unix.EINVAL) {
		return nil, nativeError("HIDIOCGRAWUNIQ", err)
	}
	if err == nil && current.hidUnique.Known && unique != current.hidUnique.Value {
		return nil, stale("opened fd unique string differs from sysfs")
	}
	if err = system.verify(path, anchor, current); err != nil {
		return nil, err
	}
	desc, err := reportdesc.Parse(descriptor)
	if err != nil {
		return nil, err
	}
	if index >= len(desc.Collections) {
		return nil, stale("collection disappeared")
	}
	collection := desc.Collections[index]
	current.endpoint.ID = expected.ID
	current.endpoint.Usage = driver.Field[driver.Usage]{Value: collection.Usage, Known: true}
	if !matches(expected, current.endpoint) {
		return nil, stale("opened metadata differs from requested endpoint")
	}
	if !collection.Supported {
		return nil, unsupported("collection does not have an unambiguous fixed Input/Output layout")
	}
	failed = false
	return &device{fd: fd, endpoint: current.endpoint, layout: collection.Layout}, nil
}

func anchorSysfs(path string) (sysfsAnchor, error) {
	fd, err := unix.Open(path, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return sysfsAnchor{}, nativeError("pin sysfs endpoint", err)
	}
	anchor := sysfsAnchor{fd: fd}
	anchor.path, err = filepath.EvalSymlinks(path)
	if err == nil {
		err = unix.Fstat(fd, &anchor.stat)
	}
	if err != nil {
		unix.Close(fd)
		return sysfsAnchor{}, nativeError("pin sysfs endpoint", err)
	}
	return anchor, nil
}

func verifySysfs(path string, anchor sysfsAnchor, item inventoryEntry) error {
	realPath, err := filepath.EvalSymlinks(path)
	var stat unix.Stat_t
	if err == nil {
		err = unix.Stat(path, &stat)
	}
	if err != nil {
		return &driver.Error{Op: "open", Kind: driver.KindStaleEndpoint, Message: "sysfs endpoint disappeared while opening", Cause: err}
	}
	if realPath != anchor.path || realPath != item.sysPath || stat.Dev != anchor.stat.Dev || stat.Ino != anchor.stat.Ino {
		return stale("sysfs endpoint association changed while opening")
	}
	return nil
}

func readDescriptor(fd int) ([]byte, error) {
	size, err := unix.IoctlGetInt(fd, unix.HIDIOCGRDESCSIZE)
	if err != nil {
		return nil, nativeError("HIDIOCGRDESCSIZE", err)
	}
	var raw unix.HIDRawReportDescriptor
	if size <= 0 || size > len(raw.Value) || size > driver.MaxDescriptorSize {
		return nil, unsupported("hidraw descriptor size exceeds supported bounds")
	}
	raw.Size = uint32(size)
	if err = unix.IoctlHIDGetDesc(fd, &raw); err != nil {
		return nil, nativeError("HIDIOCGRDESC", err)
	}
	if raw.Size != uint32(size) {
		return nil, stale("report descriptor changed while opening")
	}
	return append([]byte(nil), raw.Value[:size]...), nil
}

func readUnique(fd int) (string, error) {
	// Derive the architecture's read-direction bits from an x/sys constant.
	// HIDIOCGRAWUNIQ is _IOC(_IOC_READ, 'H', 0x08, buffer length).
	const sizeMask = 0x3fff << 16
	request := uintptr(unix.HIDIOCGRAWINFO&^(sizeMask|0xff)) | uintptr(driver.MaxMetadataSize)<<16 | 0x08
	var buffer [driver.MaxMetadataSize]byte
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), request, uintptr(unsafe.Pointer(&buffer[0])))
	runtime.KeepAlive(buffer)
	if errno != 0 {
		return "", errno
	}
	if at := bytes.IndexByte(buffer[:], 0); at >= 0 {
		return string(buffer[:at]), nil
	}
	return "", unsupported("unterminated HID unique string")
}
