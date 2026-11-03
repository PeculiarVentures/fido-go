//go:build hid_diagnostics && integration

package hid

import (
	"context"
	"github.com/PeculiarVentures/fido-go/internal/diagnostics"
	"testing"
	"time"
)

type diagnosticSequenceInventory struct {
	snapshots    []Snapshot
	polls, opens int
}

func (b *diagnosticSequenceInventory) Enumerate(context.Context, EnumerateOptions) (Snapshot, error) {
	index := b.polls
	b.polls++
	if index >= len(b.snapshots) {
		index = len(b.snapshots) - 1
	}
	return b.snapshots[index], nil
}
func (b *diagnosticSequenceInventory) Open(context.Context, Endpoint) (Conn, error) {
	b.opens++
	return nil, ErrIO
}
func TestIdenticalOperatorPhaseUsesCompleteSetDifference(t *testing.T) {
	a, b := diagnosticIdenticalEndpoint("private-a"), diagnosticIdenticalEndpoint("private-b")
	before := Snapshot{Complete: true, Endpoints: []Endpoint{a, b}}
	backend := &diagnosticSequenceInventory{snapshots: []Snapshot{{Complete: false, Endpoints: []Endpoint{b}}, {Complete: true, Endpoints: []Endpoint{b}}}}
	var action diagnosticOperatorAction
	scenario := diagnostics.Scenario{ID: "phase", Timeout: time.Second, Run: func(ctx context.Context, scope *diagnostics.Scope) error {
		opts := hidDiagnosticsOptions{OperatorPrompt: func(_ context.Context, a diagnosticOperatorAction) error { action = a; return nil }}
		d, err := identicalOperatorPhase(ctx, scope, opts, backend, before, 1, 1, 0, a)
		if err != nil {
			return err
		}
		if len(d.removed) != 1 || d.removed[0].ID != a.ID || len(d.added) != 0 {
			return ErrIO
		}
		return nil
	}}
	report, err := diagnostics.Run(context.Background(), []diagnostics.Scenario{scenario}, diagnostics.Options{})
	if err != nil || len(report.Results) != 1 || report.Results[0].Status != diagnostics.Pass || action.Phase != "identical-unplug-a" || action.KeyCount != 2 || backend.polls != 2 || backend.opens != 0 {
		t.Fatalf("phase result=%+v err=%v polls=%d opens=%d", report.Results, err, backend.polls, backend.opens)
	}
	r := report.Results[0]
	if r.Counters["phase_1_incomplete_polls"] != 1 || !r.Facts["phase_1_inventory_complete"] || !r.Facts["phase_1_expected_difference"] {
		t.Fatalf("phase evidence=%+v", r)
	}
}
func TestIdenticalOperatorPhaseRejectsUnexpectedCompleteDifference(t *testing.T) {
	a, b := diagnosticIdenticalEndpoint("a"), diagnosticIdenticalEndpoint("b")
	before := Snapshot{Complete: true, Endpoints: []Endpoint{a, b}}
	backend := &diagnosticSequenceInventory{snapshots: []Snapshot{{Complete: true}}}
	scenario := diagnostics.Scenario{ID: "phase", Timeout: time.Second, Run: func(ctx context.Context, scope *diagnostics.Scope) error {
		_, err := waitIdenticalPhase(ctx, scope, backend, before, 1, 1, 0, a)
		return err
	}}
	report, err := diagnostics.Run(context.Background(), []diagnostics.Scenario{scenario}, diagnostics.Options{})
	if err != nil || len(report.Results) != 1 || report.Results[0].Status != diagnostics.Inconclusive || backend.opens != 0 {
		t.Fatalf("unexpected transition report=%+v err=%v", report, err)
	}
}
