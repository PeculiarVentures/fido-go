//go:build hid_diagnostics

package usb_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"time"

	"github.com/PeculiarVentures/fido-go/internal/diagnostics"
	"github.com/PeculiarVentures/fido-go/internal/diagnostics/power"
	"github.com/PeculiarVentures/fido-go/pkg/hid"
	"github.com/PeculiarVentures/fido-go/pkg/transport"
	"github.com/PeculiarVentures/fido-go/pkg/transport/usb"
)

// These scenarios exercise production discovery, INIT and ExchangeHID. The HID
// suite owns report counts and native barriers; this suite consumes complete
// payloads and makes no claims about overlap inside native calls.
func usbDiagnosticScenarios(backend transport.Backend, selected []string) []diagnostics.Scenario {
	return []diagnostics.Scenario{
		{ID: "usb.multiframe-ping", Layer: "usb-session", Mode: diagnostics.Hardware, Requirements: []string{"integration-build", "native-hid"}, Timeout: time.Minute,
			Run: func(ctx context.Context, scope *diagnostics.Scope) error {
				return runUSBMultiframe(ctx, scope, backend, selected)
			}, Validate: validateUSBMultiframe},
		{ID: "usb.parallel-exchange", Layer: "usb-session", Mode: diagnostics.Hardware, Requirements: []string{"integration-build", "native-hid"}, Timeout: time.Minute,
			Run: func(ctx context.Context, scope *diagnostics.Scope) error {
				return runUSBParallel(ctx, scope, backend, selected)
			}, Validate: validateUSBParallel},
	}
}

func usbDiagnosticCapabilities() map[string]bool {
	return map[string]bool{"power-events": power.Available(), "integration-build": true, "native-hid": runtime.GOOS == "linux" || runtime.GOOS == "windows" || runtime.GOOS == "darwin" && diagnosticCGOEnabled}
}

func usbDiagnosticDevices(ctx context.Context, scope *diagnostics.Scope, backend transport.Backend, selected []string) ([]transport.DeviceDescriptor, error) {
	seen := make(map[string]bool)
	for _, id := range selected {
		if id == "" || seen[id] {
			return nil, errors.New("invalid or duplicate USB endpoint selection")
		}
		seen[id] = true
	}
	devices, err := backend.Discover(ctx)
	if err != nil {
		return nil, usbDiagnosticFailure(scope, "USB diagnostic discovery failed", err)
	}
	byID := make(map[string]transport.DeviceDescriptor, len(devices))
	for _, device := range devices {
		if device.ID == "" {
			return nil, errors.New("USB inventory contains an empty endpoint ID")
		}
		if _, ok := byID[device.ID]; ok {
			return nil, errors.New("USB inventory contains duplicate endpoints")
		}
		byID[device.ID] = device
	}
	if len(selected) == 0 {
		return devices, nil
	}
	result := make([]transport.DeviceDescriptor, 0, len(selected))
	for _, id := range selected {
		device, ok := byID[id]
		if !ok {
			return nil, diagnostics.InconclusiveReason("a selected USB endpoint is unavailable")
		}
		result = append(result, device)
	}
	return result, nil
}

func openUSBDiagnosticSession(ctx context.Context, scope *diagnostics.Scope, backend transport.Backend, device transport.DeviceDescriptor, ordinal int) (usb.HIDSession, error) {
	session, err := backend.Open(ctx, device)
	if err != nil {
		return nil, usbDiagnosticFailure(scope, "USB diagnostic session open failed", err)
	}
	prefix := fmt.Sprintf("key_%d_", ordinal)
	scope.Defer(func(cleanup context.Context) error {
		closer, ok := session.(transport.ContextCloser)
		if !ok {
			return errors.New("USB diagnostic session lacks bounded cleanup")
		}
		if err := closer.CloseContext(cleanup); err != nil {
			return usbDiagnosticFailure(scope, "USB diagnostic session cleanup failed", err)
		}
		scope.Fact(prefix+"closed", true)
		return nil
	})
	hidSession, ok := session.(usb.HIDSession)
	if !ok {
		return nil, errors.New("USB diagnostic session lacks ExchangeHID")
	}
	return hidSession, nil
}

func diagnosticUSBPing(ctx context.Context, scope *diagnostics.Scope, session usb.HIDSession, size, ordinal int) error {
	payload := make([]byte, size)
	if _, err := rand.Read(payload); err != nil {
		return errors.New("USB diagnostic payload generation failed")
	}
	if size >= 4 {
		binary.BigEndian.PutUint32(payload[:4], uint32(ordinal))
	}
	response, err := session.ExchangeHID(ctx, 1, payload)
	if err != nil {
		return usbDiagnosticFailure(scope, "USB diagnostic PING failed", err)
	}
	if !bytes.Equal(response, payload) {
		return errors.New("USB diagnostic PING response differs from its fresh payload")
	}
	return nil
}

func runUSBMultiframe(ctx context.Context, scope *diagnostics.Scope, backend transport.Backend, selected []string) error {
	devices, err := usbDiagnosticDevices(ctx, scope, backend, selected)
	if err != nil {
		return err
	}
	scope.Counter("keys_selected", uint64(len(devices)))
	if len(devices) == 0 {
		return diagnostics.InconclusiveReason("no selected USB FIDO endpoint is available")
	}
	for i, device := range devices {
		session, err := openUSBDiagnosticSession(ctx, scope, backend, device, i+1)
		if err != nil {
			return err
		}
		for _, size := range []int{0, 57, 58, 128, 1024} {
			if err := diagnosticUSBPing(ctx, scope, session, size, i+1); err != nil {
				return err
			}
			scope.Fact(fmt.Sprintf("key_%d_payload_%d_echo_verified", i+1, size), true)
		}
		scope.Counter("keys_completed", uint64(i+1))
	}
	return nil
}

func runUSBParallel(ctx context.Context, scope *diagnostics.Scope, backend transport.Backend, selected []string) error {
	devices, err := usbDiagnosticDevices(ctx, scope, backend, selected)
	if err != nil {
		return err
	}
	scope.Counter("keys_selected", uint64(len(devices)))
	if len(devices) < 2 {
		return diagnostics.InconclusiveReason("USB parallel exchange requires two independent endpoints")
	}
	sessions := make([]usb.HIDSession, 0, len(devices))
	for i, device := range devices {
		session, err := openUSBDiagnosticSession(ctx, scope, backend, device, i+1)
		if err != nil {
			return err
		}
		// Warm up through the production API before starting concurrent callers.
		if err := diagnosticUSBPing(ctx, scope, session, 24, i+1); err != nil {
			return err
		}
		sessions = append(sessions, session)
	}
	bounded, cancel := context.WithCancel(ctx)
	defer cancel()
	start := make(chan struct{})
	ready := make(chan struct{}, len(sessions))
	type outcome struct {
		index int
		err   error
	}
	done := make(chan outcome, len(sessions))
	joined := 0
	// Join callers before closing their sessions, including on discovery errors.
	scope.Defer(func(cleanup context.Context) error {
		cancel()
		for joined < len(sessions) {
			select {
			case <-done:
				joined++
			case <-cleanup.Done():
				return errors.New("USB diagnostic workers did not join")
			}
		}
		scope.Fact("workers_joined", true)
		return nil
	})
	for i, session := range sessions {
		go func() {
			ready <- struct{}{}
			select {
			case <-start:
				done <- outcome{i, diagnosticUSBPing(bounded, scope, session, 1024, i+1)}
			case <-bounded.Done():
				done <- outcome{i, bounded.Err()}
			}
		}()
	}
	for range sessions {
		select {
		case <-ready:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	scope.Fact("workers_ready_before_start", true)
	close(start)
	observed, err := usbDiagnosticDevices(ctx, scope, backend, selected)
	if err != nil {
		return err
	}
	present := make(map[string]bool, len(observed))
	for _, device := range observed {
		present[device.ID] = true
	}
	for _, device := range devices {
		if !present[device.ID] {
			return diagnostics.InconclusiveReason("USB endpoint disappeared from complete inventory")
		}
	}
	scope.Fact("complete_inventory_verified", true)
	for joined < len(sessions) {
		select {
		case result := <-done:
			joined++
			if result.err != nil {
				return errors.New("USB concurrent PING failed")
			}
			scope.Fact(fmt.Sprintf("key_%d_echo_verified", result.index+1), true)
			scope.Counter("keys_completed", uint64(joined))
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func validateUSBKeys(r diagnostics.Result, minimum uint64) error {
	keys := r.Counters["keys_selected"]
	if keys < minimum || keys != r.Counters["keys_completed"] {
		return errors.New("USB diagnostic keys did not all complete")
	}
	var e diagnostics.Evidence
	for i := uint64(1); i <= keys; i++ {
		e.RequireFacts(r, fmt.Sprintf("key_%d_closed", i))
	}
	return e.Err()
}

func validateUSBMultiframe(r diagnostics.Result) error {
	var e diagnostics.Evidence
	for i := uint64(1); i <= r.Counters["keys_selected"]; i++ {
		for _, size := range []int{0, 57, 58, 128, 1024} {
			e.RequireFacts(r, fmt.Sprintf("key_%d_payload_%d_echo_verified", i, size))
		}
	}
	return errors.Join(validateUSBKeys(r, 1), e.Err())
}

func validateUSBParallel(r diagnostics.Result) error {
	var e diagnostics.Evidence
	e.RequireFacts(r, "workers_ready_before_start", "workers_joined", "complete_inventory_verified")
	for i := uint64(1); i <= r.Counters["keys_selected"]; i++ {
		e.RequireFacts(r, fmt.Sprintf("key_%d_echo_verified", i))
	}
	return errors.Join(validateUSBKeys(r, 2), e.Err())
}

// Retain delivery categories and native codes without serializing endpoint IDs
// or native messages from the public errors.
func usbDiagnosticFailure(scope *diagnostics.Scope, message string, err error) error {
	safe := []error{errors.New(message)}
	for _, kind := range []error{context.Canceled, context.DeadlineExceeded, hid.ErrClosed, hid.ErrRemoved, hid.ErrPermission, hid.ErrBusy, hid.ErrUnsupported, hid.ErrInvalidReport, hid.ErrStaleEndpoint, hid.ErrTimeout, hid.ErrIO, hid.ErrResourceLimit} {
		if errors.Is(err, kind) {
			safe = append(safe, kind)
		}
	}
	var native *hid.NativeError
	if errors.As(err, &native) {
		scope.Native(diagnostics.NativeError{Operation: message, Domain: native.Domain, Code: native.Code})
	}
	var exchange *usb.ExchangeError
	if errors.As(err, &exchange) {
		scope.Counter("last_packets_submitted", uint64(exchange.PacketsSubmitted))
		scope.Fact("last_delivery_ambiguous", exchange.Ambiguous)
	}
	return errors.Join(safe...)
}
