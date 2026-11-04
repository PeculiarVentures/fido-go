//go:build hid_diagnostics

package client_test

import (
	"context"
	"encoding/hex"
	"errors"
	"time"

	"github.com/PeculiarVentures/fido-go/internal/diagnostics"
	"github.com/PeculiarVentures/fido-go/pkg/client"
	"github.com/PeculiarVentures/fido-go/pkg/hid"
)

func (state *clientDiagnosticState) prompt(ctx context.Context, phase string, observe func(context.Context) error) (clientDiagnosticAck, error) {
	if state.options.Operator == nil {
		return clientDiagnosticAck{}, diagnostics.InconclusiveReason("client diagnostic requires an explicit operator acknowledgment")
	}
	nonce, err := clientDiagnosticRandom(16)
	if err != nil {
		return clientDiagnosticAck{}, err
	}
	token := hex.EncodeToString(nonce)
	bounded, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	ack, err := state.options.Operator(bounded, clientDiagnosticAction{Phase: phase, TargetID: state.selector, Token: token, Observe: observe})
	if err != nil {
		return ack, err
	}
	if !ack.Approve || ack.Phase != phase || ack.Token != token || ack.TargetID != state.selector {
		return ack, errors.New("operator acknowledgment did not match the exact fresh client challenge")
	}
	if phase == "reset-confirm" && ack.Confirm != "RESET" {
		return ack, errors.New("destructive reset confirmation was not explicit")
	}
	return ack, nil
}

func (state *clientDiagnosticState) powerCycle(ctx context.Context, prefix string, reset bool) error {
	baseline, err := state.locator.List(ctx)
	if err != nil {
		return state.failure("power-cycle baseline inventory failed", err)
	}
	var target client.Device
	neighbors := make(map[string]client.Device)
	found := false
	for _, device := range baseline {
		if device.ID == state.selector {
			target = device
			found = true
		} else {
			neighbors[device.ID] = device
		}
	}
	if !found {
		return diagnostics.InconclusiveReason("exact selected target disappeared before the operator power cycle")
	}
	if state.current != nil {
		bounded, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		err = state.current.close(bounded)
		cancel()
		if err != nil {
			return err
		}
		state.current = nil
	}
	state.scope.Fact("sdk_closed_before_unplug", true)
	state.enrollmentSuspended = true
	if _, err := state.prompt(ctx, prefix+"-unplug", nil); err != nil {
		return err
	}
	absentCtx, cancelAbsent := context.WithTimeout(ctx, 5*time.Minute)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		current, listErr := state.locator.List(absentCtx)
		if listErr == nil {
			if err := validateClientDiagnosticNeighbors(current, neighbors); err != nil {
				cancelAbsent()
				return err
			}
			present := false
			for _, device := range current {
				if device.ID == state.selector {
					present = true
				}
			}
			if !present {
				break
			}
		} else if !errors.Is(listErr, hid.ErrBusy) && !errors.Is(listErr, hid.ErrResourceLimit) {
			cancelAbsent()
			return state.failure("complete absence inventory failed", listErr)
		}
		select {
		case <-absentCtx.Done():
			cancelAbsent()
			return diagnostics.InconclusiveReason("complete target absence was not observed")
		case <-ticker.C:
		}
	}
	cancelAbsent()
	lastAbsent := time.Now()
	state.scope.Fact("complete_absence_observed", true)
	var observed []client.Device
	var appearance time.Time
	observe := func(poll context.Context) error {
		rows, listErr := state.locator.List(poll)
		if listErr != nil {
			if errors.Is(listErr, hid.ErrBusy) || errors.Is(listErr, hid.ErrResourceLimit) {
				return nil
			}
			return state.failure("power-cycle reappearance inventory failed", listErr)
		}
		if err := validateClientDiagnosticNeighbors(rows, neighbors); err != nil {
			return err
		}
		candidates := 0
		for _, device := range rows {
			if _, neighbor := neighbors[device.ID]; !neighbor {
				candidates++
			}
		}
		if candidates > 1 {
			return diagnostics.InconclusiveReason("power-cycle enrollment has multiple new endpoints")
		}
		if candidates == 0 {
			lastAbsent = time.Now()
		}
		if candidates == 1 && appearance.IsZero() {
			appearance = lastAbsent
		}
		observed = rows
		return nil
	}
	ack, err := state.prompt(ctx, prefix+"-replug", observe)
	if err != nil {
		return err
	}
	if err := observe(ctx); err != nil {
		return err
	}
	if ack.EndpointID == "" {
		return diagnostics.InconclusiveReason("replug requires an explicitly enrolled exact endpoint")
	}
	var enrolled *client.Device
	for index := range observed {
		if observed[index].ID == ack.EndpointID {
			enrolled = &observed[index]
		}
	}
	if enrolled == nil {
		return diagnostics.InconclusiveReason("explicitly enrolled replacement is not present in complete inventory")
	}
	if _, neighbor := neighbors[ack.EndpointID]; neighbor {
		return errors.New("an unchanged neighbor cannot be enrolled as the power-cycled target")
	}
	if enrolled.VendorID != target.VendorID || enrolled.ProductID != target.ProductID {
		return diagnostics.InconclusiveReason("explicit replacement descriptor does not match the selected target model")
	}
	// The operator supplies the exact selector. Metadata is a rejection check,
	// never an automatic choice or evidence of durable physical identity.
	state.selector = ack.EndpointID
	state.enrollmentSuspended = false
	state.scope.Fact("explicit_reenrollment", true)
	if reset {
		state.resetAppearance = appearance
		if appearance.IsZero() || time.Since(appearance) >= 8*time.Second {
			return diagnostics.InconclusiveReason("reset enrollment missed its conservative power-up submission window")
		}
	}
	return nil
}

func validateClientDiagnosticNeighbors(current []client.Device, neighbors map[string]client.Device) error {
	seen := make(map[string]bool)
	for _, device := range current {
		if device.ID == "" || seen[device.ID] {
			return errors.New("operator inventory contains invalid endpoint addresses")
		}
		seen[device.ID] = true
	}
	for id, expected := range neighbors {
		matched := false
		for _, actual := range current {
			if actual.ID == id {
				matched = actual.VendorID == expected.VendorID && actual.ProductID == expected.ProductID && actual.Path == expected.Path && actual.SerialNumber == expected.SerialNumber
			}
		}
		if !matched {
			return diagnostics.InconclusiveReason("an unchanged neighbor disappeared or changed during exact operator enrollment")
		}
	}
	return nil
}
