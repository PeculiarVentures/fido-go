//go:build hid_diagnostics && integration

package hid

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/PeculiarVentures/fido-go/internal/diagnostics"
	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/driver"
	"testing"
	"time"
)

type identicalSequenceCloseConn struct {
	Conn
	calls int
	first error
}

func (c *identicalSequenceCloseConn) Close(context.Context) error {
	c.calls++
	if c.calls == 1 {
		return c.first
	}
	return nil
}
func TestIdenticalEpochNeverQualifiesFirstCloseFailureFromLaterSuccess(t *testing.T) {
	for _, tc := range []struct {
		name  string
		first error
	}{{"deadline", context.DeadlineExceeded}, {"generic", ErrIO}, {"permission", ErrPermission}} {
		t.Run(tc.name, func(t *testing.T) {
			conn := &identicalSequenceCloseConn{first: tc.first}
			scenario := diagnostics.Scenario{ID: "cleanup", Timeout: time.Second, Run: func(ctx context.Context, scope *diagnostics.Scope) error {
				owner := &identicalCollector{scope: scope}
				policy := &hotplugClosePolicy{scope: scope, prefix: "role_a_epoch_1_", conn: conn, absenceComplete: true, removalObserved: true}
				epoch := &identicalEpoch{owner: owner, conn: conn, role: "a", ordinal: 1, policy: policy}
				err := epoch.close(ctx)
				if !errors.Is(err, tc.first) {
					return errors.New("first close error lost")
				}
				if epoch.qualified || epoch.closeSuccess {
					return errors.New("later success misrepresented first close failure")
				}
				return nil
			}}
			report, err := diagnostics.Run(context.Background(), []diagnostics.Scenario{scenario}, diagnostics.Options{})
			if err != nil || len(report.Results) != 1 || report.Results[0].Status != diagnostics.Pass {
				t.Fatalf("report=%+v err=%v", report, err)
			}
		})
	}
}

func TestIdenticalEpochQualifiedNativeCloseRemainsAttributedOnce(t *testing.T) {
	if !platformDiagnosticCapabilities()["darwin-cgo"] {
		t.Skip("qualified native teardown requires Darwin cgo")
	}
	const secret = "private-epoch-selector"
	device := &diagnosticHotplugErrorDevice{fakeDevice: newFake(secret)}
	backend := &Native{open: func(driver.Endpoint) (driver.Device, error) { return device, nil }}
	probe := &diagnosticHotplugProbe{state: hotplugCloseProof{RealProbe: true, SameProbe: true, WriterExited: true, WriterJoined: true, DeviceClosed: true}}
	scenario := diagnostics.Scenario{ID: "cleanup", Timeout: 3 * time.Second, Run: func(ctx context.Context, scope *diagnostics.Scope) error {
		conn, err := backend.Open(ctx, Endpoint{ID: secret})
		if err != nil {
			return err
		}
		owner := &identicalCollector{scope: scope}
		policy := &hotplugClosePolicy{scope: scope, prefix: "role_a_epoch_1_", conn: conn, probe: probe, absenceComplete: true, removalObserved: true}
		epoch := &identicalEpoch{owner: owner, conn: conn, role: "a", ordinal: 1, policy: policy}
		scope.Defer(epoch.cleanup)
		if err := epoch.close(ctx); err != nil {
			return err
		}
		if err := epoch.close(ctx); err != nil {
			return err
		}
		return nil
	}}
	report, err := diagnostics.Run(context.Background(), []diagnostics.Scenario{scenario}, diagnostics.Options{})
	if err != nil || len(report.Results) != 1 {
		t.Fatalf("run=%v", err)
	}
	r := report.Results[0]
	if r.Status != diagnostics.Pass || !r.Cleanup.Complete || !r.Facts["role_a_epoch_1_expected_post_removal_close_diagnostic"] || r.Facts["role_a_epoch_1_native_close_success"] || device.closes != 1 || probe.closes != 1 {
		t.Fatalf("cleanup result=%+v device=%d probe=%d", r, device.closes, probe.closes)
	}
	count := 0
	for _, n := range r.NativeErrors {
		if n.Operation == "role_a_epoch_1_Close" && n.Domain == "iokit" && n.Code == 0xe00002c2 {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("attributed close diagnostics=%d", count)
	}
	data, err := json.Marshal(report)
	if err != nil || bytes.Contains(data, []byte(secret)) {
		t.Fatal("report leaked endpoint selector")
	}
}
