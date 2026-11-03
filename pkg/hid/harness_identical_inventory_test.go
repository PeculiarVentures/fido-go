//go:build hid_diagnostics

package hid

import (
	"errors"

	"github.com/PeculiarVentures/fido-go/internal/diagnostics"
	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/driver"
)

var errIdenticalAmbiguous = errors.New("unlabelled identical-key recovery is ambiguous")

// Initial order carries no operator role or physical identity. A/B labels can
// only be enrolled later from an explicit operator action and complete set diff.
func classifyIdenticalInitial(snapshot Snapshot, selected []EndpointID) ([]Endpoint, error) {
	if err := validateIdenticalInventory(snapshot); err != nil {
		return nil, err
	}
	if len(snapshot.Endpoints) != 2 {
		return nil, diagnostics.InconclusiveReason("identical-key qualification requires exactly two USB FIDO endpoints and no unrelated endpoints")
	}
	if len(selected) != 0 && len(selected) != 2 {
		return nil, diagnostics.InconclusiveReason("identical-key qualification requires both endpoint selectors")
	}
	if len(selected) == 2 {
		if selected[0] == selected[1] {
			return nil, errors.New("duplicate identical-key endpoint selector")
		}
		for _, id := range selected {
			if id != snapshot.Endpoints[0].ID && id != snapshot.Endpoints[1].ID {
				return nil, diagnostics.InconclusiveReason("an explicitly selected identical-key endpoint is unavailable")
			}
		}
	}
	if !sameIdenticalDescriptor(snapshot.Endpoints[0], snapshot.Endpoints[1]) {
		return nil, diagnostics.InconclusiveReason("selected endpoints do not have the same known USB FIDO descriptor")
	}
	return append([]Endpoint(nil), snapshot.Endpoints...), nil
}

// Difference never selects a replacement by model. Retained native addresses
// must keep their known descriptor, including interface number and usage.
func classifyIdenticalDifference(before, current Snapshot) (removed, added []Endpoint, err error) {
	if err = validateIdenticalInventory(before); err != nil {
		return nil, nil, err
	}
	if err = validateIdenticalInventory(current); err != nil {
		return nil, nil, err
	}
	previous := make(map[EndpointID]Endpoint, len(before.Endpoints))
	for _, endpoint := range before.Endpoints {
		previous[endpoint.ID] = endpoint
	}
	present := make(map[EndpointID]bool, len(current.Endpoints))
	for _, endpoint := range current.Endpoints {
		present[endpoint.ID] = true
		if expected, retained := previous[endpoint.ID]; retained {
			if !sameIdenticalDescriptor(expected, endpoint) {
				return nil, nil, diagnostics.InconclusiveReason("a retained endpoint changed descriptor during identical-key qualification")
			}
		} else {
			added = append(added, endpoint)
		}
	}
	for _, endpoint := range before.Endpoints {
		if !present[endpoint.ID] {
			removed = append(removed, endpoint)
		}
	}
	return removed, added, nil
}

// A complete inventory with two indistinguishable candidates is intentionally
// ambiguous. This helper performs no Open and never chooses the first match.
func classifyIdenticalUnlabelled(candidates []Endpoint) (Endpoint, error) {
	if err := validateIdenticalInventory(Snapshot{Complete: true, Endpoints: candidates}); err != nil {
		return Endpoint{}, err
	}
	if len(candidates) == 0 {
		return Endpoint{}, diagnostics.InconclusiveReason("no current endpoint is available for operator enrollment")
	}
	if len(candidates) != 1 {
		return Endpoint{}, errors.Join(errIdenticalAmbiguous, diagnostics.InconclusiveReason("unlabelled recovery is ambiguous and requires explicit operator enrollment"))
	}
	return candidates[0], nil
}

func classifyIdenticalSurvivor(current Snapshot, expected Endpoint) (Endpoint, error) {
	if err := validateIdenticalInventory(current); err != nil {
		return Endpoint{}, err
	}
	for _, endpoint := range current.Endpoints {
		if endpoint.ID == expected.ID && sameIdenticalDescriptor(expected, endpoint) {
			return endpoint, nil
		}
	}
	return Endpoint{}, diagnostics.InconclusiveReason("the expected surviving endpoint is absent or changed descriptor")
}

func validateIdenticalInventory(snapshot Snapshot) error {
	if !snapshot.Complete {
		return diagnostics.InconclusiveReason("identical-key inventory is incomplete")
	}
	if len(snapshot.Endpoints) > driver.MaxInventoryEndpoints {
		return errors.New("identical-key inventory exceeds endpoint bound")
	}
	seen := make(map[EndpointID]bool, len(snapshot.Endpoints))
	for _, endpoint := range snapshot.Endpoints {
		if endpoint.ID == "" || seen[endpoint.ID] {
			return errors.New("identical-key inventory contains an empty or duplicate address")
		}
		seen[endpoint.ID] = true
		if !sameIdenticalDescriptor(endpoint, endpoint) {
			return diagnostics.InconclusiveReason("identical-key inventory lacks a qualified known USB FIDO descriptor")
		}
	}
	return nil
}

// Optional strings and paths are deliberately excluded: these fields neither
// label operator roles nor prove durable physical identity or port topology.
func sameIdenticalDescriptor(a, b Endpoint) bool {
	return a.VendorID.Known && b.VendorID.Known && a.VendorID.Value == b.VendorID.Value &&
		a.ProductID.Known && b.ProductID.Known && a.ProductID.Value == b.ProductID.Value &&
		a.Usage.Known && b.Usage.Known && a.Usage.Value == (Usage{Page: 0xf1d0, ID: 1}) && a.Usage.Value == b.Usage.Value &&
		a.Bus == BusUSB && b.Bus == BusUSB && a.Interface.Known && b.Interface.Known &&
		a.Interface.Value >= 0 && a.Interface.Value <= 255 && a.Interface.Value == b.Interface.Value
}
