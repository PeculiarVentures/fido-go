//go:build linux

package linux

import (
	"errors"
	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/driver"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenIDOnlyAndRejectReusedAssociation(t *testing.T) {
	const address = "/sys/devices/example/hidraw0"
	desc := []byte{0x06, 0xd0, 0xf1, 0x09, 1, 0xa1, 1, 0x75, 8, 0x95, 64, 0x81, 2, 0x91, 2, 0xc0}
	devnum := unix.Mkdev(1, 3)
	for _, tc := range []struct {
		name  string
		reuse bool
	}{{"id only", false}, {"same minor reused", true}} {
		t.Run(tc.name, func(t *testing.T) {
			serial := "first"
			opened := false
			closedDevice := false
			sys := openSystem{
				anchor: func(string) (sysfsAnchor, error) { return sysfsAnchor{fd: 10}, nil },
				inspect: func(string, bool) (inventoryEntry, error) {
					return inventoryEntry{sysPath: address, dev: devnum, descriptor: desc, hidUnique: driver.Field[string]{Known: true, Value: serial}, endpoint: driver.Endpoint{Path: "/dev/hidraw0", Bus: driver.BusUSB, VendorID: driver.Field[uint16]{Known: true, Value: 0x1050}, ProductID: driver.Field[uint16]{Known: true, Value: 0x407}, Serial: driver.Field[string]{Known: true, Value: serial}}}, nil
				},
				verify: func(_ string, _ sysfsAnchor, _ inventoryEntry) error {
					if tc.reuse && opened {
						return stale("association changed")
					}
					return nil
				},
				open: func(string) (int, error) {
					opened = true
					if tc.reuse {
						serial = "second"
					}
					return 11, nil
				}, close: func(fd int) error {
					if fd == 11 {
						closedDevice = true
					}
					return nil
				},
				fstat: func(_ int, st *unix.Stat_t) error { st.Mode = unix.S_IFCHR; st.Rdev = devnum; return nil }, info: func(int) (*unix.HIDRawDevInfo, error) {
					return &unix.HIDRawDevInfo{Bustype: 3, Vendor: 0x1050, Product: 0x407}, nil
				}, descriptor: func(int) ([]byte, error) { return desc, nil }, unique: func(int) (string, error) { return serial, nil },
			}
			got, err := openWithSystem(driver.Endpoint{ID: endpointID(address, 0)}, sys)
			if tc.reuse {
				var e *driver.Error
				if !errors.As(err, &e) || e.Kind != driver.KindStaleEndpoint || !closedDevice || got != nil {
					t.Fatalf("reused open=%v %v closed=%v", got, err, closedDevice)
				}
				return
			}
			if err != nil || got == nil || got.Endpoint().Serial.Value != "first" || closedDevice {
				t.Fatalf("ID only open=%v %v closed=%v", got, err, closedDevice)
			}
		})
	}
}

func TestVerifySysfsRejectsRecreatedDirectory(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "hidraw0")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	anchor, err := anchorSysfs(path)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(anchor.fd)
	item := inventoryEntry{sysPath: path}
	if err := verifySysfs(path, anchor, item); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	var native *driver.Error
	if err := verifySysfs(path, anchor, item); !errors.As(err, &native) || native.Kind != driver.KindStaleEndpoint {
		t.Fatalf("recreated association error=%v", err)
	}
}
