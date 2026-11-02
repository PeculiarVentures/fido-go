//go:build integration

package usb_test

import (
	"bytes"
	"context"
	"github.com/PeculiarVentures/fido-go/pkg/transport/usb"
	"os"
	"testing"
	"time"
)

// TestNativeHIDHardware performs read-only CTAPHID operations on every discovered key.
func TestNativeHIDHardware(t *testing.T) {
	if os.Getenv("FIDO_HID_TEST") != "1" {
		t.Skip("set FIDO_HID_TEST=1 to run read-only hardware checks")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	b := usb.NewHIDBackend()
	devices, err := b.Discover(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) == 0 {
		t.Fatal("no FIDO USB devices discovered")
	}
	for i, device := range devices {
		session, err := b.Open(ctx, device)
		if err != nil {
			t.Fatalf("device %d open: %v", i, err)
		}
		h, ok := session.(usb.HIDSession)
		if !ok {
			_ = session.Close()
			t.Fatal("session lacks HID exchange")
		}
		ping := []byte{0x43, 0x54, 0x41, 0x50}
		reply, err := h.ExchangeHID(ctx, 1, ping)
		if err != nil || !bytes.Equal(reply, ping) {
			_ = session.Close()
			t.Fatalf("device %d INIT/PING: %v", i, err)
		}
		reply, err = session.Exchange(ctx, []byte{4})
		if err != nil || len(reply) == 0 || reply[0] != 0 {
			_ = session.Close()
			t.Fatalf("device %d GetInfo failed: %v", i, err)
		}
		if err = session.Close(); err != nil {
			t.Fatalf("device %d close: %v", i, err)
		}
		t.Logf("device %d VID:PID %04x:%04x passed", i, device.VendorID, device.ProductID)
	}
}
