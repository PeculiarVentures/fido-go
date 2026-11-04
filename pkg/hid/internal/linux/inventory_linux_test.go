//go:build linux

package linux

import (
	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/driver"
	"os"
	"path/filepath"
	"testing"
)

func fixtureWrite(t *testing.T, path, value string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(value), 0600); err != nil {
		t.Fatal(err)
	}
}
func TestInspectUsesOnlyTokenUSBAttributes(t *testing.T) {
	for _, tc := range []struct {
		name    string
		token   bool
		bus     string
		resolve bool
	}{
		{"token attributes", true, "0003", true}, {"missing attributes", false, "0003", true}, {"strings not requested", true, "0003", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			hub := filepath.Join(root, "hub")
			token := filepath.Join(hub, "token")
			iface := filepath.Join(token, "1-1:1.2")
			hid := filepath.Join(iface, "hid")
			node := filepath.Join(root, "hidraw0")
			for _, d := range []string{hid, node} {
				if err := os.MkdirAll(d, 0700); err != nil {
					t.Fatal(err)
				}
			}
			for _, p := range []string{"manufacturer", "product", "serial"} {
				fixtureWrite(t, filepath.Join(root, p), "root-"+p)
				fixtureWrite(t, filepath.Join(hub, p), "hub-"+p)
				if tc.token {
					fixtureWrite(t, filepath.Join(token, p), "token-"+p)
				}
			}
			fixtureWrite(t, filepath.Join(token, "idVendor"), "1050\n")
			fixtureWrite(t, filepath.Join(token, "idProduct"), "0407\n")
			fixtureWrite(t, filepath.Join(iface, "bInterfaceNumber"), "02\n")
			fixtureWrite(t, filepath.Join(node, "dev"), "1:3\n")
			fixtureWrite(t, filepath.Join(node, "uevent"), "DEVNAME=null\n")
			fixtureWrite(t, filepath.Join(hid, "uevent"), "HID_ID="+tc.bus+":00001050:00000407\n")
			fixtureWrite(t, filepath.Join(hid, "report_descriptor"), string([]byte{0x06, 0xd0, 0xf1, 0x09, 1, 0xa1, 1, 0xc0}))
			if err := os.Symlink(hid, filepath.Join(node, "device")); err != nil {
				t.Fatal(err)
			}
			got, err := inspect(node, tc.resolve)
			if err != nil {
				t.Fatal(err)
			}
			if got.endpoint.Bus != driver.BusUSB || !got.endpoint.Interface.Known || got.endpoint.Interface.Value != 2 {
				t.Fatalf("bus/interface: %+v", got.endpoint)
			}
			for _, p := range []struct {
				name  string
				field driver.Field[string]
			}{{"manufacturer", got.endpoint.Manufacturer}, {"product", got.endpoint.Product}, {"serial", got.endpoint.Serial}} {
				wantKnown := tc.token && tc.resolve
				if p.field.Known != wantKnown || wantKnown && p.field.Value != "token-"+p.name {
					t.Errorf("%s=%+v, want token known=%v", p.name, p.field, wantKnown)
				}
			}
		})
	}
}

func TestReadUSBMetadataPreservesFallbackAndBusScope(t *testing.T) {
	root := t.TempDir()
	token := filepath.Join(root, "token")
	iface := filepath.Join(token, "interface")
	hid := filepath.Join(iface, "hid")
	if err := os.MkdirAll(hid, 0700); err != nil {
		t.Fatal(err)
	}
	fixtureWrite(t, filepath.Join(token, "idVendor"), "1050")
	fixtureWrite(t, filepath.Join(token, "idProduct"), "0407")
	fixtureWrite(t, filepath.Join(token, "serial"), "")
	fixtureWrite(t, filepath.Join(iface, "bInterfaceNumber"), "02")
	fixtureWrite(t, filepath.Join(root, "product"), "wrong-hub")
	endpoint := driver.Endpoint{Bus: driver.BusUSB, Product: driver.Field[string]{Known: true, Value: "hid product"}, Serial: driver.Field[string]{Known: true, Value: "hid serial"}}
	readUSBMetadata(hid, &endpoint, true)
	if !endpoint.Serial.Known || endpoint.Serial.Value != "" || endpoint.Product.Value != "hid product" || !endpoint.Product.Known || !endpoint.Interface.Known || endpoint.Interface.Value != 2 {
		t.Fatalf("USB metadata: %+v", endpoint)
	}
	bluetooth := driver.Endpoint{Bus: driver.BusBluetooth}
	readUSBMetadata(hid, &bluetooth, true)
	if bluetooth.Serial.Known || bluetooth.Product.Known || bluetooth.Interface.Known {
		t.Fatalf("non-USB inherited USB metadata: %+v", bluetooth)
	}
}
