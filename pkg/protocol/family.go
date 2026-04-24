package protocol

import "fmt"

// Family identifies a FIDO protocol family handled by the SDK.
type Family string

const (
	// FamilyCTAP1 identifies the CTAP1 protocol family.
	//
	// The SDK uses the protocol-family name rather than a separate U2F alias so
	// that CTAP1 and CTAP2 stay parallel at the public API boundary.
	FamilyCTAP1 Family = "ctap1"
	// FamilyCTAP2 identifies the CTAP2 protocol family.
	FamilyCTAP2 Family = "ctap2"
)

// IsKnown reports whether the family is supported by the public SDK surface.
func (family Family) IsKnown() bool {
	switch family {
	case FamilyCTAP1, FamilyCTAP2:
		return true
	default:
		return false
	}
}

// Validate reports an error when the family is not recognized.
func (family Family) Validate() error {
	if family.IsKnown() {
		return nil
	}

	return &UnknownFamilyError{Family: family}
}

// UnknownFamilyError reports an unsupported protocol family value.
type UnknownFamilyError struct {
	Family Family
}

// Error returns the validation failure message.
func (err *UnknownFamilyError) Error() string {
	return fmt.Sprintf("protocol: unknown family %q", err.Family)
}
