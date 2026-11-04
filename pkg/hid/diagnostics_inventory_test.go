//go:build hid_diagnostics && integration

package hid

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/PeculiarVentures/fido-go/internal/diagnostics"
	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/driver"
)

type diagnosticInventoryBackend struct {
	snapshot            Snapshot
	enumerations, opens int
}

func (b *diagnosticInventoryBackend) Enumerate(context.Context, EnumerateOptions) (Snapshot, error) {
	b.enumerations++
	return b.snapshot, nil
}
func (b *diagnosticInventoryBackend) Open(context.Context, Endpoint) (Conn, error) {
	b.opens++
	return nil, nil
}
func TestDiagnosticsRejectsDuplicateEndpointSelectionsAndInventory(t *testing.T) {
	const secret = EndpointID("secret-endpoint-marker")
	b := &diagnosticInventoryBackend{snapshot: Snapshot{Complete: true, Endpoints: []Endpoint{{ID: secret}}}}
	result, err := diagnosticHardwareEndpointsWithBackend(context.Background(), b, []EndpointID{secret, secret})
	if err == nil || len(result) != 0 || b.enumerations != 0 || b.opens != 0 || strings.Contains(err.Error(), string(secret)) {
		t.Fatalf("duplicate selector result=%v err=%v enumerations=%d opens=%d", result, err, b.enumerations, b.opens)
	}
	for _, selection := range [][]EndpointID{nil, {secret}} {
		b = &diagnosticInventoryBackend{snapshot: Snapshot{Complete: true, Endpoints: []Endpoint{{ID: secret}, {ID: secret}}}}
		result, err = diagnosticHardwareEndpointsWithBackend(context.Background(), b, selection)
		if err == nil || len(result) != 0 || b.enumerations != 1 || b.opens != 0 || strings.Contains(err.Error(), string(secret)) {
			t.Fatalf("duplicate inventory result=%v err=%v enumerations=%d opens=%d", result, err, b.enumerations, b.opens)
		}
	}
}

func TestDiagnosticsRecoveryDescriptorRequiresKnownMatchingMetadata(t *testing.T) {
	base := Endpoint{VendorID: Field[uint16]{Known: true, Value: 0x1050}, ProductID: Field[uint16]{Known: true, Value: 0x407}, Usage: Field[Usage]{Known: true, Value: Usage{Page: 0xf1d0, ID: 1}}, Bus: BusUSB, Interface: Field[int]{Known: true, Value: 0}}
	changedID := base
	changedID.ID = "new-address"
	if !sameRecoveryDescriptor(base, changedID) {
		t.Fatal("matching observed metadata must allow a changed endpoint address")
	}
	cases := []Endpoint{base, base, base, base}
	cases[0].VendorID.Known = false
	cases[1].ProductID.Value++
	cases[2].Usage.Known = false
	cases[3].Interface.Known = false
	for i, actual := range cases {
		if sameRecoveryDescriptor(base, actual) {
			t.Errorf("nonmatching or unknown descriptor accepted at case %d", i)
		}
	}
}

func TestDiagnosticsStaleExactOpenRequiresEvidenceOfRemovalOrStaleness(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{{"removed", ErrRemoved, true}, {"stale", ErrStaleEndpoint, true}, {"wrapped removed", fmt.Errorf("native: %w", ErrRemoved), true}, {"resource", ErrResourceLimit, false}, {"permission", ErrPermission, false}, {"invalid", ErrInvalidArgument, false}, {"generic IO", ErrIO, false}, {"canceled", context.Canceled, false}, {"deadline", context.DeadlineExceeded, false}, {"busy", ErrBusy, false}, {"nil", nil, false}} {
		t.Run(tc.name, func(t *testing.T) {
			if got := qualifiesStaleExactOpenRejection(tc.err); got != tc.want {
				t.Fatalf("qualifies=%v want=%v", got, tc.want)
			}
		})
	}
}

func TestDiagnosticsUnqualifiedOpenErrorRetainsCategoryAndNativeCodeWithoutSelector(t *testing.T) {
	const secret = "private-stale-selector"
	original := &Error{Op: "open", Endpoint: EndpointID(secret), Kind: ErrPermission, Native: &NativeError{Domain: "iokit", Code: 0xe00002e2, Message: secret}}
	safe := diagnosticSafeError(nil, original)
	var native *NativeError
	if qualifiesStaleExactOpenRejection(safe) || !errors.Is(safe, ErrPermission) || !errors.As(safe, &native) || native.Domain != "iokit" || native.Code != 0xe00002e2 || strings.Contains(safe.Error(), secret) {
		t.Fatalf("sanitized error=%v native=%+v", safe, native)
	}
}

func TestDiagnosticsNeighborClassificationNeverSubstitutesChangedAddress(t *testing.T) {
	base := Endpoint{ID: "private-old", VendorID: Field[uint16]{Known: true, Value: 1}, ProductID: Field[uint16]{Known: true, Value: 2}, Usage: Field[Usage]{Known: true, Value: Usage{Page: 0xf1d0, ID: 1}}, Bus: BusUSB, Interface: Field[int]{Known: true, Value: 0}}
	newID := base
	newID.ID = "private-new"
	changed := base
	changed.Interface.Value = 1
	for _, tc := range []struct {
		name                                string
		current                             []Endpoint
		exact, sameID, mismatch, newAddress bool
		models, descriptors                 int
	}{{"exact", []Endpoint{base}, true, true, false, false, 1, 1}, {"absent", nil, false, false, false, false, 0, 0}, {"new address", []Endpoint{newID}, false, false, false, true, 1, 1}, {"metadata change", []Endpoint{changed}, false, true, true, false, 1, 0}} {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyHotplugNeighbor(base, tc.current)
			if got.ExactMatch != tc.exact || got.SameIDPresent != tc.sameID || got.SameIDDescriptorMismatch != tc.mismatch || got.SameDescriptorNewID != tc.newAddress || got.VIDPIDCount != tc.models || got.DescriptorCount != tc.descriptors {
				t.Fatalf("classification=%+v", got)
			}
			if tc.name == "metadata change" && !got.InterfaceChanged {
				t.Fatal("interface change unreported")
			}
		})
	}
}

func TestDiagnosticsHotplugCloseQualificationRequiresEveryProof(t *testing.T) {
	proof := hotplugCloseProof{AbsenceComplete: true, RemovalObserved: true, RealProbe: true, SameProbe: true, WriterExited: true, WriterJoined: true, DeviceClosed: true, CoreDone: true, LeaseReleased: true}
	expected := &Error{Op: "close", Endpoint: "private-marker", Kind: ErrIO, Native: &NativeError{Domain: "iokit", Code: 0xe00002c2, Message: "private-marker"}}
	if !qualifiesHotplugCloseDiagnostic(expected, proof) {
		t.Fatal("fully evidenced close diagnostic rejected")
	}
	for _, tc := range []struct {
		name    string
		missing func(*hotplugCloseProof)
	}{{"absence", func(p *hotplugCloseProof) { p.AbsenceComplete = false }}, {"removal", func(p *hotplugCloseProof) { p.RemovalObserved = false }}, {"real probe", func(p *hotplugCloseProof) { p.RealProbe = false }}, {"same probe", func(p *hotplugCloseProof) { p.SameProbe = false }}, {"writer exit", func(p *hotplugCloseProof) { p.WriterExited = false }}, {"writer join", func(p *hotplugCloseProof) { p.WriterJoined = false }}, {"device close", func(p *hotplugCloseProof) { p.DeviceClosed = false }}, {"core done", func(p *hotplugCloseProof) { p.CoreDone = false }}, {"lease released", func(p *hotplugCloseProof) { p.LeaseReleased = false }}} {
		t.Run(tc.name, func(t *testing.T) {
			p := proof
			tc.missing(&p)
			if qualifiesHotplugCloseDiagnostic(expected, p) {
				t.Fatal("missing proof accepted")
			}
		})
	}
	for _, tc := range []struct {
		name string
		err  error
	}{{"nil", nil}, {"wrong code", &Error{Op: "close", Kind: ErrIO, Native: &NativeError{Domain: "iokit", Code: 1}}}, {"wrong domain", &Error{Op: "close", Kind: ErrIO, Native: &NativeError{Domain: "pthread", Code: 0xe00002c2}}}, {"wrong operation", &Error{Op: "write", Kind: ErrIO, Native: &NativeError{Domain: "iokit", Code: 0xe00002c2}}}, {"additional native error", errors.Join(expected, &NativeError{Domain: "pthread", Code: 5})}, {"extra permission", errors.Join(expected, ErrPermission)}, {"extra resource", errors.Join(expected, ErrResourceLimit)}, {"extra unrelated", errors.Join(expected, errors.New("unrelated failure"))}, {"wrong public kind", &Error{Op: "close", Kind: ErrPermission, Native: &NativeError{Domain: "iokit", Code: 0xe00002c2}}}, {"wrong driver kind", &driver.Error{Op: "close", Kind: driver.KindPermission, Domain: "iokit", Code: 0xe00002c2}}, {"deadline", errors.Join(expected, context.DeadlineExceeded)}, {"canceled", errors.Join(expected, context.Canceled)}} {
		t.Run(tc.name, func(t *testing.T) {
			if qualifiesHotplugCloseDiagnostic(tc.err, proof) {
				t.Fatalf("unqualified error accepted: %v", tc.err)
			}
		})
	}
}

type diagnosticHotplugErrorDevice struct {
	*fakeDevice
	closes int
}

func (d *diagnosticHotplugErrorDevice) Close() error {
	d.closes++
	close(d.closed)
	return &driver.Error{Op: "close", Kind: driver.KindIO, Domain: "iokit", Code: 0xe00002c2, Message: "secret-close-message"}
}

type diagnosticHotplugProbe struct {
	state  hotplugCloseProof
	closes int
}

func (p *diagnosticHotplugProbe) proof() hotplugCloseProof { return p.state }
func (p *diagnosticHotplugProbe) close() error             { p.closes++; return nil }
func TestDiagnosticsHotplugClosePolicyRetainsNativeErrorAndIsIdempotent(t *testing.T) {
	const secret = "private-cleanup-endpoint"
	device := &diagnosticHotplugErrorDevice{fakeDevice: newFake(secret)}
	backend := &Native{open: func(driver.Endpoint) (driver.Device, error) { return device, nil }}
	probe := &diagnosticHotplugProbe{state: hotplugCloseProof{RealProbe: true, SameProbe: true, WriterExited: true, WriterJoined: true, DeviceClosed: true}}
	scenario := diagnostics.Scenario{ID: "cleanup", Timeout: 3 * time.Second, Run: func(ctx context.Context, scope *diagnostics.Scope) error {
		conn, err := backend.Open(ctx, Endpoint{ID: secret})
		if err != nil {
			return err
		}
		policy := hotplugClosePolicy{scope: scope, prefix: "key_1_", conn: conn, probe: probe, absenceComplete: true, removalObserved: true}
		scope.Defer(func(ctx context.Context) error { return policy.cleanup(ctx, conn) })
		return policy.close(ctx, conn)
	}}
	report, err := diagnostics.Run(context.Background(), []diagnostics.Scenario{scenario}, diagnostics.Options{})
	if err != nil || len(report.Results) != 1 {
		t.Fatalf("run=%v", err)
	}
	r := report.Results[0]
	if r.Status != diagnostics.Pass || !r.Cleanup.Complete || r.Facts["key_1_native_close_success"] || !r.Facts["key_1_teardown_complete"] || !r.Facts["key_1_expected_post_removal_close_diagnostic"] || device.closes != 1 || probe.closes != 1 {
		t.Fatalf("result=%+v device closes=%d probe closes=%d", r, device.closes, probe.closes)
	}
	var b bytes.Buffer
	if err := diagnostics.WriteJSON(&b, report); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), secret) || strings.Contains(b.String(), "secret-close-message") {
		t.Fatal("report leaked endpoint or native message")
	}
	found := false
	for _, n := range r.NativeErrors {
		if n.Domain == "iokit" && n.Code == 0xe00002c2 {
			found = true
		}
	}
	if !found {
		t.Fatal("native close diagnostic not retained")
	}
}
