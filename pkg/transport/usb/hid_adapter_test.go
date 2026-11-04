package usb

import (
	"context"
	"errors"
	"github.com/PeculiarVentures/fido-go/pkg/hid"
	"github.com/PeculiarVentures/fido-go/pkg/transport"
	"testing"
	"time"
)

type fakeBackend struct {
	snapshot hid.Snapshot
	opened   []hid.Endpoint
	conn     hid.Conn
}

func (f *fakeBackend) Enumerate(context.Context, hid.EnumerateOptions) (hid.Snapshot, error) {
	return f.snapshot, nil
}
func (f *fakeBackend) Open(_ context.Context, e hid.Endpoint) (hid.Conn, error) {
	f.opened = append(f.opened, e)
	return f.conn, nil
}
func fidoEndpoint(id, path string) hid.Endpoint {
	return hid.Endpoint{ID: hid.EndpointID(id), Path: path, Bus: hid.BusUSB, Usage: hid.Field[hid.Usage]{Known: true, Value: hid.Usage{Page: 0xf1d0, ID: 1}}}
}
func TestHIDBackendExactSelectionAndIncompleteInventory(t *testing.T) {
	f := &fakeBackend{snapshot: hid.Snapshot{Complete: true, Endpoints: []hid.Endpoint{fidoEndpoint("A", "shared"), fidoEndpoint("a", "shared")}}, conn: newFakeHIDDevice()}
	b, err := NewHIDBackendWithHID(f)
	if err != nil {
		t.Fatal(err)
	}
	devices, err := b.Discover(context.Background())
	if err != nil || len(devices) != 2 {
		t.Fatalf("discover %v %v", devices, err)
	}
	if _, err = b.Open(context.Background(), transport.DeviceDescriptor{Path: "shared"}); !errors.Is(err, hid.ErrInvalidArgument) {
		t.Fatalf("ambiguous path: %v", err)
	}
	s, err := b.Open(context.Background(), transport.DeviceDescriptor{ID: "a"})
	if err != nil || len(f.opened) != 1 || f.opened[0].ID != "a" {
		t.Fatalf("exact selection: %v %v", f.opened, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	f.snapshot.Complete = false
	f.snapshot.Warnings = []error{errors.New("partial")}
	if _, err = b.Discover(context.Background()); err == nil {
		t.Fatal("partial inventory accepted")
	}
	// A listed exact endpoint is positive evidence even in partial inventory.
	s, err = b.Open(context.Background(), transport.DeviceDescriptor{ID: "A"})
	if err != nil || f.opened[len(f.opened)-1].ID != "A" {
		t.Fatalf("exact endpoint in partial inventory: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// Absence from partial inventory does not establish removal.
	if _, err = b.Open(context.Background(), transport.DeviceDescriptor{ID: "missing"}); err == nil || errors.Is(err, hid.ErrRemoved) || errors.Is(err, transport.ErrDisconnected) {
		t.Fatalf("missing endpoint in partial inventory: %v", err)
	}
	// A path-only selection cannot prove uniqueness in partial inventory.
	f.snapshot.Endpoints = f.snapshot.Endpoints[:1]
	if _, err = b.Open(context.Background(), transport.DeviceDescriptor{Path: "shared"}); err == nil {
		t.Fatal("path-only open accepted partial inventory")
	}
}

type blockingWriteConn struct{ *fakeHIDDevice }

func (c *blockingWriteConn) Write(ctx context.Context, _ hid.Report) (hid.WriteResult, error) {
	<-ctx.Done()
	return hid.WriteResult{Outcome: hid.OutcomeUnknown}, ctx.Err()
}

func TestExchangeBoundsStuckReportWrite(t *testing.T) {
	previous := hidWriteTimeout
	hidWriteTimeout = 20 * time.Millisecond
	defer func() { hidWriteTimeout = previous }()
	f := &blockingWriteConn{fakeHIDDevice: newFakeHIDDevice()}
	s := &hidSession{conn: f, layout: f.Layout(), channelID: testChannelID, reportSize: hidReportSize}
	defer s.Close()
	done := make(chan error, 1)
	go func() {
		_, err := s.ExchangeHID(context.Background(), 0x42, []byte{1})
		done <- err
	}()
	select {
	case err := <-done:
		var ex *ExchangeError
		if !errors.Is(err, hid.ErrTimeout) || !errors.As(err, &ex) || !ex.Ambiguous {
			t.Fatalf("stuck write error: %v (%+v)", err, ex)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("exchange without caller deadline hung on a stuck report write")
	}
}

type failingWriteConn struct {
	*fakeHIDDevice
	writes  int
	failAt  int
	outcome hid.WriteOutcome
}

func (c *failingWriteConn) Write(_ context.Context, _ hid.Report) (hid.WriteResult, error) {
	c.writes++
	if c.writes == c.failAt {
		return hid.WriteResult{Outcome: c.outcome}, errors.New("injected write failure")
	}
	return hid.WriteResult{Outcome: hid.OutcomeCompleted}, nil
}
func TestExchangeErrorPreservesPartialSubmission(t *testing.T) {
	for _, tc := range []struct {
		name      string
		failAt    int
		outcome   hid.WriteOutcome
		packets   int
		ambiguous bool
	}{{"first rejected", 1, hid.OutcomeNotSubmitted, 0, false}, {"first unknown", 1, hid.OutcomeUnknown, 0, true}, {"second rejected", 2, hid.OutcomeNotSubmitted, 1, true}} {
		t.Run(tc.name, func(t *testing.T) {
			f := &failingWriteConn{fakeHIDDevice: newFakeHIDDevice(), failAt: tc.failAt, outcome: tc.outcome}
			s := &hidSession{conn: f, layout: f.Layout(), channelID: testChannelID, reportSize: hidReportSize}
			defer s.Close()
			_, err := s.ExchangeHID(context.Background(), 0x42, make([]byte, 100))
			var ex *ExchangeError
			if !errors.As(err, &ex) || ex.Stage != StageRequest || ex.PacketsSubmitted != tc.packets || ex.Outcome != tc.outcome || ex.Ambiguous != tc.ambiguous {
				t.Fatalf("exchange error=%+v (%v)", ex, err)
			}
		})
	}
}
