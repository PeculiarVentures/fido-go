package diagnostics

import (
	"errors"
	"fmt"
)

// Evidence collects validation failures without changing a result's observations.
// Its zero value is ready for use.
type Evidence struct{ errors []error }

// Errorf records a failure using scenario-owned, non-secret field names.
func (e *Evidence) Errorf(format string, args ...any) {
	e.errors = append(e.errors, fmt.Errorf(format, args...))
}

// RequireFacts requires each named observation to have been recorded as true.
func (e *Evidence) RequireFacts(r Result, names ...string) {
	for _, name := range names {
		if !r.Facts[name] {
			e.Errorf("missing evidence %s", name)
		}
	}
}

// Err returns all validation failures, or nil when the evidence is complete.
func (e *Evidence) Err() error { return errors.Join(e.errors...) }
