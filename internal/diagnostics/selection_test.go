package diagnostics_test

import (
	"context"
	"testing"

	"github.com/PeculiarVentures/fido-go/internal/diagnostics"
)

func TestParseDiagnosticScenarioIDs(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  int
		bad   bool
	}{{"", 0, false}, {"hardware.multiframe-ping", 1, false}, {"hardware.multiframe-ping,hardware.parallel-exchange", 2, false}, {",x", 0, true}, {"x,", 0, true}, {"x,x", 0, true}, {"x, y", 0, true}} {
		ids, err := diagnostics.ParseScenarioIDs(tc.input)
		if (err != nil) != tc.bad || !tc.bad && len(ids) != tc.want {
			t.Errorf("input %q ids=%v err=%v", tc.input, ids, err)
		}
	}
}

func TestDiagnosticScenarioSelectionRejectsUnknownAndDuplicatesBeforeExecution(t *testing.T) {
	ran := false
	scenarios := []diagnostics.Scenario{{ID: "first", Run: func(context.Context, *diagnostics.Scope) error { ran = true; return nil }}, {ID: "second", Run: func(context.Context, *diagnostics.Scope) error { ran = true; return nil }}}
	for _, bad := range [][]string{{"first", "missing"}, {"first", "first"}} {
		selected, err := diagnostics.Select(scenarios, bad)
		if err == nil || len(selected) != 0 || ran {
			t.Fatalf("selection=%v err=%v ran=%v", bad, err, ran)
		}
	}
	selected, err := diagnostics.Select(scenarios, []string{"second"})
	if err != nil || len(selected) != 1 || selected[0].ID != "second" || ran {
		t.Fatalf("selected=%+v err=%v ran=%v", selected, err, ran)
	}
}
