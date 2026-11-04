//go:build hid_diagnostics

package hid

import (
	"errors"
	"testing"
)

func diagnosticIdenticalEndpoint(id EndpointID) Endpoint {
	return Endpoint{ID: id, VendorID: Field[uint16]{Known: true, Value: 0x08e6}, ProductID: Field[uint16]{Known: true, Value: 0x34d2}, Usage: Field[Usage]{Known: true, Value: Usage{Page: 0xf1d0, ID: 1}}, Interface: Field[int]{Known: true}, Bus: BusUSB}
}
func TestIdenticalInitialRejectsAmbiguousOrIncompleteInventory(t *testing.T) {
	a, b := diagnosticIdenticalEndpoint("private-a"), diagnosticIdenticalEndpoint("private-b")
	good := Snapshot{Complete: true, Endpoints: []Endpoint{a, b}}
	got, err := classifyIdenticalInitial(good, nil)
	if err != nil || len(got) != 2 {
		t.Fatalf("valid pair rejected: %v", err)
	}
	for _, tc := range []struct {
		name     string
		s        Snapshot
		selected []EndpointID
	}{{"incomplete", Snapshot{Endpoints: []Endpoint{a, b}}, nil}, {"one", Snapshot{Complete: true, Endpoints: []Endpoint{a}}, nil}, {"duplicate", Snapshot{Complete: true, Endpoints: []Endpoint{a, a}}, nil}, {"extra", Snapshot{Complete: true, Endpoints: []Endpoint{a, b, diagnosticIdenticalEndpoint("extra")}}, nil}, {"selected duplicate", good, []EndpointID{a.ID, a.ID}}, {"selected unavailable", good, []EndpointID{a.ID, "missing"}}} {
		t.Run(tc.name, func(t *testing.T) {
			if endpoints, err := classifyIdenticalInitial(tc.s, tc.selected); err == nil || len(endpoints) != 0 {
				t.Fatalf("unqualified pair accepted: %v", err)
			}
		})
	}
	unknown := b
	unknown.Interface.Known = false
	if got, err := classifyIdenticalInitial(Snapshot{Complete: true, Endpoints: []Endpoint{a, unknown}}, nil); err == nil || len(got) != 0 {
		t.Fatal("unknown interface accepted")
	}
	for _, n := range []int{-1, 256} {
		invalid := b
		invalid.Interface.Value = n
		if got, err := classifyIdenticalInitial(Snapshot{Complete: true, Endpoints: []Endpoint{a, invalid}}, nil); err == nil || len(got) != 0 {
			t.Fatalf("invalid interface %d accepted", n)
		}
	}
	different := b
	different.ProductID.Value++
	if got, err := classifyIdenticalInitial(Snapshot{Complete: true, Endpoints: []Endpoint{a, different}}, nil); err == nil || len(got) != 0 {
		t.Fatal("different model accepted")
	}
}
func TestIdenticalInventoryDifferenceAndUnlabelledAmbiguity(t *testing.T) {
	a, b := diagnosticIdenticalEndpoint("a"), diagnosticIdenticalEndpoint("b")
	before := Snapshot{Complete: true, Endpoints: []Endpoint{a, b}}
	removed, added, err := classifyIdenticalDifference(before, Snapshot{Complete: true, Endpoints: []Endpoint{b}})
	if err != nil || len(removed) != 1 || removed[0].ID != a.ID || len(added) != 0 {
		t.Fatalf("removal classification incorrect: %v", err)
	}
	if _, err := classifyIdenticalUnlabelled([]Endpoint{a, b}); !errors.Is(err, errIdenticalAmbiguous) {
		t.Fatal("ambiguous candidates were not explicitly rejected")
	}
	if got, err := classifyIdenticalUnlabelled([]Endpoint{b}); err != nil || got.ID != b.ID {
		t.Fatalf("single enrolled candidate: %v", err)
	}
	changed := b
	changed.Interface.Value++
	if _, _, err := classifyIdenticalDifference(before, Snapshot{Complete: true, Endpoints: []Endpoint{changed}}); err == nil {
		t.Fatal("retained address with changed descriptor accepted")
	}
	if _, _, err := classifyIdenticalDifference(before, Snapshot{Endpoints: []Endpoint{b}}); err == nil {
		t.Fatal("incomplete observation accepted")
	}
	// Equal addresses after a swap do not prove physical identity: set difference
	// deliberately returns no substitution claim and performs no device Open.
	removed, added, err = classifyIdenticalDifference(before, before)
	if err != nil || len(removed) != 0 || len(added) != 0 {
		t.Fatal("unchanged address set misclassified")
	}
}

func TestIdenticalSurvivorRequiresExactAddressAndMatchingMetadata(t *testing.T) {
	a, b := diagnosticIdenticalEndpoint("a"), diagnosticIdenticalEndpoint("b")
	if got, err := classifyIdenticalSurvivor(Snapshot{Complete: true, Endpoints: []Endpoint{a, b}}, b); err != nil || got.ID != b.ID {
		t.Fatalf("exact survivor rejected: %v", err)
	}
	if _, err := classifyIdenticalSurvivor(Snapshot{Complete: true, Endpoints: []Endpoint{a}}, b); err == nil {
		t.Fatal("same-model neighbor substituted for survivor")
	}
	changed := b
	changed.Interface.Value = 1
	if _, err := classifyIdenticalSurvivor(Snapshot{Complete: true, Endpoints: []Endpoint{changed}}, b); err == nil {
		t.Fatal("same address with changed descriptor accepted")
	}
}
