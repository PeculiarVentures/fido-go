//go:build hid_diagnostics

package hid

import (
	"fmt"
	"io"
	"strings"
	"testing"
)

func writeDiagnosticOperatorAction(w io.Writer, action diagnosticOperatorAction) error {
	if (action.Phase != "unplug" && action.Phase != "replug") || action.KeyOrdinal < 1 {
		return fmt.Errorf("invalid diagnostic operator action")
	}
	_, err := fmt.Fprintf(w, "HID_OPERATOR phase=%s key=%d vid=%04x pid=%04x\n", action.Phase, action.KeyOrdinal, action.VendorID, action.ProductID)
	return err
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
