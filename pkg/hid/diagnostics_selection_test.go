//go:build hid_diagnostics

package hid

import (
	"fmt"
	"io"
	"strings"
	"testing"
)

func writeDiagnosticOperatorAction(w io.Writer, action diagnosticOperatorAction) error {
	switch action.Phase {
	case "unplug", "replug":
		if action.KeyOrdinal < 1 {
			return fmt.Errorf("invalid diagnostic operator action")
		}
		_, err := fmt.Fprintf(w, "HID_OPERATOR phase=%s key=%d vid=%04x pid=%04x\n", action.Phase, action.KeyOrdinal, action.VendorID, action.ProductID)
		return err
	case "sleep-idle", "sleep-exchange":
		if action.KeyCount < 1 {
			return fmt.Errorf("invalid diagnostic operator action")
		}
		_, err := fmt.Fprintf(w, "HID_OPERATOR phase=%s keys=%d\n", action.Phase, action.KeyCount)
		return err
	default:
		return fmt.Errorf("invalid diagnostic operator action")
	}
}
func TestDiagnosticOperatorEventContainsOnlySafeFields(t *testing.T) {
	var b strings.Builder
	if err := writeDiagnosticOperatorAction(&b, diagnosticOperatorAction{Phase: "unplug", KeyOrdinal: 2, VendorID: 0x1050, ProductID: 0x0407}); err != nil {
		t.Fatal(err)
	}
	if got, want := b.String(), "HID_OPERATOR phase=unplug key=2 vid=1050 pid=0407\n"; got != want {
		t.Fatalf("event=%q want=%q", got, want)
	}
	if err := writeDiagnosticOperatorAction(&b, diagnosticOperatorAction{Phase: "other", KeyOrdinal: 1}); err == nil {
		t.Fatal("unknown phase accepted")
	}
}

func TestDiagnosticSleepOperatorEventContainsOnlySafeFields(t *testing.T) {
	for _, phase := range []string{"sleep-idle", "sleep-exchange"} {
		var b strings.Builder
		action := diagnosticOperatorAction{Phase: phase, KeyCount: 2, KeyOrdinal: 99, VendorID: 0x1234, ProductID: 0x5678}
		if err := writeDiagnosticOperatorAction(&b, action); err != nil {
			t.Fatal(err)
		}
		want := fmt.Sprintf("HID_OPERATOR phase=%s keys=2\n", phase)
		if b.String() != want {
			t.Fatalf("event=%q want=%q", b.String(), want)
		}
	}
	if err := writeDiagnosticOperatorAction(io.Discard, diagnosticOperatorAction{Phase: "sleep-idle"}); err == nil {
		t.Fatal("zero count accepted")
	}
}
