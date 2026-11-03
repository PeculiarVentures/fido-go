package diagnostics

import (
	"errors"
	"strings"
)

// ParseScenarioIDs parses exact comma-separated IDs without echoing selectors
// into errors. Empty input selects the entire catalog.
func ParseScenarioIDs(value string) ([]string, error) {
	if value == "" {
		return nil, nil
	}
	ids := strings.Split(value, ",")
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if id == "" || strings.TrimSpace(id) != id || seen[id] {
			return nil, errors.New("invalid or duplicate diagnostic scenario selector")
		}
		seen[id] = true
	}
	return ids, nil
}

// Select resolves all requested IDs before any scenario is allowed to run.
func Select(scenarios []Scenario, ids []string) ([]Scenario, error) {
	if len(ids) == 0 {
		return scenarios, nil
	}
	known := make(map[string]Scenario, len(scenarios))
	for _, scenario := range scenarios {
		if _, exists := known[scenario.ID]; exists {
			return nil, errors.New("duplicate diagnostic scenario definition")
		}
		known[scenario.ID] = scenario
	}
	selected := make([]Scenario, 0, len(ids))
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		scenario, ok := known[id]
		if !ok {
			return nil, errors.New("unknown diagnostic scenario ID")
		}
		if seen[id] {
			return nil, errors.New("duplicate diagnostic scenario ID")
		}
		seen[id] = true
		selected = append(selected, scenario)
	}
	return selected, nil
}
