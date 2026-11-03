//go:build hid_diagnostics

package hid

import (
	"context"
	"fmt"
	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/diagnostics"
	"io"
	"strings"
	"testing"
)

func parseDiagnosticScenarioIDs(value string) ([]string, error) {
	if value == "" {
		return nil, nil
	}
	ids := strings.Split(value, ",")
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if id == "" || strings.TrimSpace(id) != id || seen[id] {
			return nil, fmt.Errorf("invalid or duplicate diagnostic scenario selector")
		}
		seen[id] = true
	}
	return ids, nil
}
func TestParseDiagnosticScenarioIDs(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  int
		bad   bool
	}{{"", 0, false}, {"hardware.multiframe-ping", 1, false}, {"hardware.multiframe-ping,hardware.parallel-exchange", 2, false}, {",x", 0, true}, {"x,", 0, true}, {"x,x", 0, true}, {"x, y", 0, true}} {
		ids, err := parseDiagnosticScenarioIDs(tc.input)
		if (err != nil) != tc.bad || !tc.bad && len(ids) != tc.want {
			t.Errorf("input %q ids=%v err=%v", tc.input, ids, err)
		}
	}
}
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

func TestDiagnosticScenarioSelectionRejectsUnknownAndDuplicatesBeforeExecution(t *testing.T) {
	ran := false
	scenarios := []diagnostics.Scenario{{ID: "first", Run: func(context.Context, *diagnostics.Scope) error { ran = true; return nil }}, {ID: "second", Run: func(context.Context, *diagnostics.Scope) error { ran = true; return nil }}}
	for _, bad := range [][]string{{"first", "missing"}, {"first", "first"}} {
		selected, err := selectDiagnosticScenarios(scenarios, bad)
		if err == nil || len(selected) != 0 || ran {
			t.Fatalf("selection=%v err=%v ran=%v", bad, err, ran)
		}
	}
	selected, err := selectDiagnosticScenarios(scenarios, []string{"second"})
	if err != nil || len(selected) != 1 || selected[0].ID != "second" || ran {
		t.Fatalf("selected=%+v err=%v ran=%v", selected, err, ran)
	}
}
