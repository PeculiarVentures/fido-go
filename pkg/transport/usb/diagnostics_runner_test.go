//go:build hid_diagnostics

package usb_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PeculiarVentures/fido-go/internal/diagnostics"
	"github.com/PeculiarVentures/fido-go/pkg/hid"
	"github.com/PeculiarVentures/fido-go/pkg/transport/usb"
	wirehid "github.com/PeculiarVentures/fido-go/pkg/wire/hid"
)

// The fixture implements reports only. Production USB code must perform INIT,
// readiness PING, channel allocation, fragmentation and response reassembly.
type diagnosticEchoBackend struct {
	endpoints []hid.Endpoint
	opened    []*diagnosticEchoConn
	corrupt   bool
}

func (b *diagnosticEchoBackend) Enumerate(context.Context, hid.EnumerateOptions) (hid.Snapshot, error) {
	return hid.Snapshot{Complete: true, Endpoints: b.endpoints}, nil
}

func (b *diagnosticEchoBackend) Open(_ context.Context, endpoint hid.Endpoint) (hid.Conn, error) {
	c := &diagnosticEchoConn{endpoint: endpoint, input: make(chan hid.Report, 128), closed: make(chan struct{}), corrupt: b.corrupt}
	b.opened = append(b.opened, c)
	return c, nil
}

type diagnosticEchoConn struct {
	endpoint                hid.Endpoint
	input                   chan hid.Report
	closed                  chan struct{}
	once                    sync.Once
	initializations, closes atomic.Int32
	assembler               *wirehid.Assembler
	cid                     uint32
	command                 byte
	corrupt                 bool
}

func (c *diagnosticEchoConn) Endpoint() hid.Endpoint { return c.endpoint }
func (c *diagnosticEchoConn) Layout() hid.ReportLayout {
	return hid.ReportLayout{Input: hid.ReportSpec{Size: 64}, Output: hid.ReportSpec{Size: 64}}
}
func (c *diagnosticEchoConn) Write(ctx context.Context, report hid.Report) (hid.WriteResult, error) {
	if err := ctx.Err(); err != nil {
		return hid.WriteResult{Outcome: hid.OutcomeNotSubmitted}, err
	}
	packet := report.Data
	if packet[4]&0x80 != 0 {
		c.cid, c.command = binary.BigEndian.Uint32(packet[:4]), packet[4]
		codec, err := wirehid.NewCodec(c.cid, c.command, 64)
		if err != nil {
			return hid.WriteResult{}, err
		}
		c.assembler = codec.NewAssembler()
	}
	if err := c.assembler.Add(packet); err != nil {
		return hid.WriteResult{}, err
	}
	if c.assembler.Done() {
		payload, err := c.assembler.Payload()
		if err != nil {
			return hid.WriteResult{}, err
		}
		if c.command == 0x86 {
			c.initializations.Add(1)
			response := make([]byte, 17)
			copy(response, payload)
			binary.BigEndian.PutUint32(response[8:12], 0x01020304)
			payload = response
		} else if c.corrupt && len(payload) == 1024 {
			payload[0] ^= 0xff
		}
		codec, err := wirehid.NewCodec(c.cid, c.command, 64)
		if err != nil {
			return hid.WriteResult{}, err
		}
		packets, err := codec.Fragment(payload)
		if err != nil {
			return hid.WriteResult{}, err
		}
		for _, data := range packets {
			c.input <- hid.Report{Data: data}
		}
	}
	return hid.WriteResult{Outcome: hid.OutcomeCompleted}, nil
}
func (c *diagnosticEchoConn) Read(ctx context.Context, wait time.Duration) (hid.Report, error) {
	var timeout <-chan time.Time
	if wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		timeout = timer.C
	}
	select {
	case report := <-c.input:
		return report, nil
	case <-ctx.Done():
		return hid.Report{}, ctx.Err()
	case <-timeout:
		return hid.Report{}, hid.ErrTimeout
	case <-c.closed:
		return hid.Report{}, hid.ErrClosed
	}
}
func (c *diagnosticEchoConn) Close(context.Context) error {
	c.once.Do(func() { c.closes.Add(1); close(c.closed) })
	return nil
}

func TestUSBDiagnosticsUseProductionSessionsAndRejectCorruptEchoes(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		fixture := &diagnosticEchoBackend{corrupt: corrupt}
		for _, id := range []hid.EndpointID{"private-endpoint-a", "private-endpoint-b"} {
			fixture.endpoints = append(fixture.endpoints, hid.Endpoint{ID: id, Bus: hid.BusUSB, Usage: hid.Field[hid.Usage]{Known: true, Value: hid.Usage{Page: 0xf1d0, ID: 1}}})
		}
		backend, err := usb.NewHIDBackendWithHID(fixture)
		if err != nil {
			t.Fatal(err)
		}
		report, err := diagnostics.Run(context.Background(), usbDiagnosticScenarios(backend, nil), diagnostics.Options{Capabilities: map[string]bool{"integration-build": true, "native-hid": true}, EnabledModes: map[diagnostics.Mode]bool{diagnostics.Hardware: true}})
		if err != nil {
			t.Fatal(err)
		}
		want := diagnostics.Pass
		if corrupt {
			want = diagnostics.Fail
		}
		for _, result := range report.Results {
			if result.ScenarioID == "usb.parallel-exchange" && (!result.Facts["workers_ready_before_start"] || !result.Facts["workers_joined"]) {
				t.Errorf("parallel workers were not started and joined: %+v", result)
			}
			if result.Status != want || !result.Cleanup.Complete || result.Layer != "usb-session" {
				t.Errorf("result=%+v want=%s", result, want)
			}
		}
		data, err := json.Marshal(report)
		if err != nil || bytes.Contains(data, []byte("private-endpoint")) {
			t.Fatalf("report leaked endpoint selector: err=%v", err)
		}
		for _, conn := range fixture.opened {
			if conn.initializations.Load() != 1 || conn.closes.Load() != 1 {
				t.Errorf("INIT=%d cleanup=%d", conn.initializations.Load(), conn.closes.Load())
			}
		}
	}
}
