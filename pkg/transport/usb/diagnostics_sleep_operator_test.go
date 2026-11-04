//go:build hid_diagnostics && integration

package usb_test

import (
	"fmt"
	"io"
	"strings"
	"testing"
)

func writeUSBOperatorAction(w io.Writer, phase string, keys int) error {
	if (phase != "usb-sleep-idle" && phase != "usb-sleep-exchange") || keys != 2 {
		return fmt.Errorf("invalid USB sleep diagnostic operator action")
	}
	_, err := fmt.Fprintf(w, "USB_OPERATOR phase=%s keys=%d\n", phase, keys)
	return err
}
func TestUSBOperatorSleepEventsContainOnlySafeFields(t *testing.T) {
	for _, phase := range []string{"usb-sleep-idle", "usb-sleep-exchange"} {
		var b strings.Builder
		if err := writeUSBOperatorAction(&b, phase, 2); err != nil {
			t.Fatal(err)
		}
		if got, want := b.String(), "USB_OPERATOR phase="+phase+" keys=2\n"; got != want {
			t.Fatalf("event=%q want=%q", got, want)
		}
	}
	for _, tc := range []struct {
		phase string
		keys  int
	}{{"usb-sleep-idle", 1}, {"usb-sleep-exchange", 0}, {"unplug", 2}, {"sleep-idle", 2}} {
		if err := writeUSBOperatorAction(io.Discard, tc.phase, tc.keys); err == nil {
			t.Errorf("accepted phase %q keys %d", tc.phase, tc.keys)
		}
	}
}
