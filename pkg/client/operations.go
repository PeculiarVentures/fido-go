package client

import (
	"encoding/binary"
	"fmt"

	"github.com/PeculiarVentures/fido-go/pkg/ctap1"
	"github.com/PeculiarVentures/fido-go/pkg/ctap2"
)

const (
	authenticatorDataMinimumLength     = 37
	attestedCredentialDataHeaderLength = 18
	authenticatorDataFlagUserPresent   = 0x01
	authenticatorDataFlagUserVerified  = 0x04
	authenticatorDataFlagAttestedCred  = 0x40
	fidoU2FAttestationFormat           = "fido-u2f"
)

// User identifies the account bound to a registration request.
type User struct {
	ID          []byte
	Name        string
	DisplayName string
}

// UserVerificationPolicy declares how strongly an operation should require user verification.
type UserVerificationPolicy string

const (
	// UserVerificationDiscouraged allows operations to proceed without user verification.
	UserVerificationDiscouraged UserVerificationPolicy = "discouraged"
	// UserVerificationPreferred requests user verification when it is available.
	UserVerificationPreferred UserVerificationPolicy = "preferred"
	// UserVerificationRequired requires user verification for the operation to proceed.
	UserVerificationRequired UserVerificationPolicy = "required"
)

// Requirement describes how strongly an operation should request a capability.
type Requirement string

const (
	// RequirementDiscouraged avoids requesting the capability.
	RequirementDiscouraged Requirement = "discouraged"
	// RequirementPreferred uses the protocol default behavior.
	RequirementPreferred Requirement = "preferred"
	// RequirementRequired explicitly requests the capability.
	RequirementRequired Requirement = "required"
)

// AuthenticatorSelection declares common policy applied before protocol-specific overrides.
type AuthenticatorSelection struct {
	UserPresence     Requirement
	UserVerification UserVerificationPolicy
}

// CTAP1RegistrationOptions contains CTAP1-specific registration overrides.
type CTAP1RegistrationOptions struct {
	AppIDHash []byte
}

// CTAP2RegistrationOptions contains CTAP2-specific registration overrides.
type CTAP2RegistrationOptions struct {
	RPName               string
	CredentialParameters []ctap2.CredentialParameter
	ExcludeList          []ctap2.CredentialDescriptor
}

// RegistrationRequest describes a semantic registration flow with protocol-specific overrides.
type RegistrationRequest struct {
	ChallengeHash []byte
	RPID          string
	User          User
	Selection     AuthenticatorSelection

	CTAP1 *CTAP1RegistrationOptions
	CTAP2 *CTAP2RegistrationOptions
}

// RegisterRequest is the compatibility alias for RegistrationRequest.
type RegisterRequest = RegistrationRequest

// RegistrationResult contains normalized registration details plus raw protocol responses.
type RegistrationResult struct {
	Protocol          ProtocolFamily
	CredentialID      []byte
	AttestationFormat string
	UserPresent       bool
	UserVerified      bool

	RawCTAP1 *ctap1.RegisterResponse
	RawCTAP2 *ctap2.MakeCredentialResponse
}

// CTAP1AuthenticationOptions contains CTAP1-specific authentication overrides.
type CTAP1AuthenticationOptions struct {
	AppIDHash []byte
	KeyHandle []byte
	Control   ctap1.Control
}

// CTAP2AuthenticationOptions contains CTAP2-specific authentication overrides.
type CTAP2AuthenticationOptions struct {
	AllowList []ctap2.CredentialDescriptor
}

// AuthenticationRequest describes a semantic authentication flow with protocol-specific overrides.
type AuthenticationRequest struct {
	ChallengeHash []byte
	RPID          string
	Selection     AuthenticatorSelection

	CTAP1 *CTAP1AuthenticationOptions
	CTAP2 *CTAP2AuthenticationOptions
}

// AuthenticateRequest is the compatibility alias for AuthenticationRequest.
type AuthenticateRequest = AuthenticationRequest

// AuthenticationResult contains normalized authentication details plus raw protocol responses.
type AuthenticationResult struct {
	Protocol     ProtocolFamily
	CredentialID []byte
	Signature    []byte
	SignCount    uint32
	UserPresent  bool
	UserVerified bool

	RawCTAP1 *ctap1.AuthenticateResponse
	RawCTAP2 *ctap2.GetAssertionResponse
}

// AssertionResult is the compatibility alias for AuthenticationResult.
type AssertionResult = AuthenticationResult

type parsedAuthenticatorData struct {
	UserPresent  bool
	UserVerified bool
	SignCount    uint32
	CredentialID []byte
}

func parseAuthenticatorData(data []byte) (*parsedAuthenticatorData, error) {
	if len(data) < authenticatorDataMinimumLength {
		return nil, fmt.Errorf("client: authenticator data is %d bytes, need at least %d", len(data), authenticatorDataMinimumLength)
	}

	flags := data[32]
	parsed := &parsedAuthenticatorData{
		UserPresent:  flags&authenticatorDataFlagUserPresent != 0,
		UserVerified: flags&authenticatorDataFlagUserVerified != 0,
		SignCount:    binary.BigEndian.Uint32(data[33:37]),
	}

	if flags&authenticatorDataFlagAttestedCred == 0 {
		return parsed, nil
	}

	offset := authenticatorDataMinimumLength
	if len(data) < offset+attestedCredentialDataHeaderLength {
		return nil, fmt.Errorf("client: authenticator data is missing attested credential data")
	}
	offset += 16
	credentialIDLength := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	if len(data) < offset+credentialIDLength {
		return nil, fmt.Errorf("client: authenticator data credential id length %d exceeds payload", credentialIDLength)
	}
	parsed.CredentialID = append([]byte(nil), data[offset:offset+credentialIDLength]...)
	return parsed, nil
}

func (selection AuthenticatorSelection) normalizedUserPresence() Requirement {
	switch selection.UserPresence {
	case RequirementDiscouraged, RequirementRequired:
		return selection.UserPresence
	default:
		return RequirementPreferred
	}
}

func (selection AuthenticatorSelection) normalizedUserVerification() UserVerificationPolicy {
	switch selection.UserVerification {
	case UserVerificationPreferred, UserVerificationRequired:
		return selection.UserVerification
	default:
		return UserVerificationDiscouraged
	}
}

func defaultCTAP1AuthenticateControl(selection AuthenticatorSelection) ctap1.Control {
	if selection.normalizedUserPresence() == RequirementDiscouraged {
		return ctap1.ControlDontEnforceUserPresenceAndSign
	}
	return ctap1.ControlEnforceUserPresenceAndSign
}
