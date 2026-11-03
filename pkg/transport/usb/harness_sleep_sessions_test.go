//go:build hid_diagnostics

package usb_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/PeculiarVentures/fido-go/internal/diagnostics"
	"github.com/PeculiarVentures/fido-go/pkg/hid"
	"github.com/PeculiarVentures/fido-go/pkg/transport"
	"github.com/PeculiarVentures/fido-go/pkg/transport/usb"
)

type usbSleepSession struct {
	scope        *diagnostics.Scope
	ordinal      int
	session      usb.HIDSession
	closer       transport.ContextCloser
	raw          *usbSleepHIDConn
	endpoint     hid.Endpoint
	closeFailure error
	fresh        bool
}

func usbSleepKey(ordinal int) string { return fmt.Sprintf("key_%d_", ordinal) }

func openUSBSleepSession(ctx context.Context, scope *diagnostics.Scope, backend *usb.HIDBackend, decorated *usbSleepHIDBackend, device transport.DeviceDescriptor, ordinal int, fresh bool) (*usbSleepSession, error) {
	opened, err := backend.Open(ctx, device)
	if err != nil {
		return nil, err
	}
	record := &usbSleepSession{scope: scope, ordinal: ordinal, fresh: fresh}
	// Register before interface checks or initialization can fail. The production
	// session owns native cleanup throughout; no raw handle is ever closed here.
	scope.Defer(func(cleanup context.Context) error {
		if record.closer == nil {
			if closer, ok := opened.(transport.ContextCloser); ok {
				record.closer = closer
			} else {
				return errors.New("USB sleep session lacks bounded cleanup")
			}
		}
		return record.close(cleanup)
	})
	record.session, _ = opened.(usb.HIDSession)
	record.closer, _ = opened.(transport.ContextCloser)
	if record.session == nil || record.closer == nil {
		return nil, errors.New("USB sleep backend did not return production ExchangeHID and CloseContext")
	}
	record.raw, err = decorated.connection(hid.EndpointID(device.ID))
	if err != nil {
		return nil, err
	}
	record.endpoint = record.raw.Endpoint()
	return record, nil
}
func (record *usbSleepSession) close(ctx context.Context) error {
	err := record.closer.CloseContext(ctx)
	// Sticky evidence applies only to explicit public Session.CloseContext calls,
	// not the canceled lower Conn.Close wait used by production retire().
	if err != nil && record.closeFailure == nil {
		record.closeFailure = err
	}
	p := usbSleepKey(record.ordinal)
	if record.fresh {
		record.scope.Fact(p+"fresh_closed", err == nil && record.closeFailure == nil)
	} else {
		record.scope.Fact(p+"old_close_success", err == nil && record.closeFailure == nil)
		record.scope.Fact(p+"old_close_error_recorded", record.closeFailure != nil)
		count := uint64(0)
		if record.closeFailure != nil {
			count = 1
		}
		record.scope.Counter(p+"old_close_errors", count)
	}
	return usbSleepFailure(record.scope, "USB sleep explicit session cleanup failed", record.closeFailure)
}

func usbSleepPayload(size, ordinal int) ([]byte, error) {
	payload := make([]byte, size)
	if _, err := rand.Read(payload); err != nil {
		return nil, errors.New("USB sleep payload generation failed")
	}
	if len(payload) >= 4 {
		binary.BigEndian.PutUint32(payload[:4], uint32(ordinal))
	}
	return payload, nil
}
func warmUSBSleepSessions(ctx context.Context, scope *diagnostics.Scope, backend *usb.HIDBackend, decorated *usbSleepHIDBackend, devices []transport.DeviceDescriptor) ([]*usbSleepSession, error) {
	records := make([]*usbSleepSession, 0, len(devices))
	for index, device := range devices {
		bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
		record, err := openUSBSleepSession(bounded, scope, backend, decorated, device, index+1, false)
		if err == nil {
			payload, payloadErr := usbSleepPayload(24, index+1)
			err = payloadErr
			if err == nil {
				response, pingErr := record.session.ExchangeHID(bounded, 1, payload)
				err = pingErr
				if err == nil && !bytes.Equal(response, payload) {
					err = errors.New("USB warmup PING returned a different fresh payload")
				}
			}
		}
		cancel()
		if err != nil {
			return nil, err
		}
		scope.Fact(usbSleepKey(index+1)+"warmup_ping_verified", true)
		scope.Fact(usbSleepKey(index+1)+"physical_identity_proven", false)
		records = append(records, record)
	}
	scope.Fact("all_warmup_pings_verified", true)
	return records, nil
}
func closeUSBSleepOldSessions(scope *diagnostics.Scope, records []*usbSleepSession) error {
	var failures []error
	for _, record := range records {
		bounded, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		err := record.close(bounded)
		cancel()
		if err != nil {
			failures = append(failures, err)
		}
	}
	scope.Fact("all_old_sessions_closed", len(failures) == 0)
	return errors.Join(failures...)
}

func recoverUSBSleepSessions(ctx context.Context, scope *diagnostics.Scope, backend *usb.HIDBackend, decorated *usbSleepHIDBackend, old []*usbSleepSession) error {
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	devices, err := usbDiagnosticDevices(bounded, scope, backend, nil)
	if err != nil {
		return err
	}
	snapshot := decorated.snapshot()
	if !snapshot.Complete {
		return diagnostics.InconclusiveReason("fresh production USB discovery did not have complete HID inventory")
	}
	expected := make([]hid.Endpoint, len(old))
	for index, record := range old {
		expected[index] = record.endpoint
	}
	candidates, err := selectUSBSleepRecovery(expected, snapshot.Endpoints)
	if err != nil {
		return err
	}
	byID := make(map[string]transport.DeviceDescriptor, len(devices))
	for _, device := range devices {
		byID[device.ID] = device
	}
	// Validate the complete mapping before making any automatic recovery Open.
	for _, candidate := range candidates {
		if _, present := byID[string(candidate.ID)]; !present {
			return diagnostics.InconclusiveReason("recovery candidate was absent from fresh production USB discovery")
		}
	}
	var failures []error
	completed := uint64(0)
	for index, candidate := range candidates {
		p := usbSleepKey(index + 1)
		exact := candidate.ID == expected[index].ID
		scope.Fact(p+"fresh_discovery_complete", true)
		scope.Fact(p+"recovery_metadata_verified", true)
		scope.Fact(p+"recovery_exact_retained", exact)
		scope.Fact(p+"recovery_unique_unclaimed", !exact)
		scope.Counter(p+"fresh_probe_attempts", 1)
		probeCtx, cancelProbe := context.WithTimeout(bounded, 10*time.Second)
		record, probeErr := openUSBSleepSession(probeCtx, scope, backend, decorated, byID[string(candidate.ID)], index+1, true)
		if probeErr == nil {
			payload, payloadErr := usbSleepPayload(24, index+101)
			probeErr = payloadErr
			if probeErr == nil {
				response, pingErr := record.session.ExchangeHID(probeCtx, 1, payload)
				probeErr = pingErr
				if probeErr == nil && !bytes.Equal(response, payload) {
					probeErr = errors.New("fresh production USB recovery PING returned a different payload")
				}
			}
			if probeErr == nil {
				scope.Fact(p+"fresh_init_ping_verified", true)
			}
		}
		cancelProbe()
		if record != nil {
			closeCtx, cancelClose := context.WithTimeout(context.Background(), 3*time.Second)
			probeErr = errors.Join(probeErr, record.close(closeCtx))
			cancelClose()
		}
		if probeErr != nil {
			failures = append(failures, probeErr)
		} else {
			completed++
		}
		scope.Counter("keys_completed", completed)
	}
	scope.Fact("all_fresh_recoveries_ping_verified", completed == uint64(len(old)))
	return errors.Join(failures...)
}
