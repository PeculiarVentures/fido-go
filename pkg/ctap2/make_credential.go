package ctap2

import (
	"fmt"

	"github.com/PeculiarVentures/fido-go/pkg/protocol"
)

// CommandMakeCredential is the CTAP2 authenticatorMakeCredential command identifier.
const CommandMakeCredential byte = 0x01

// MakeCredentialCommand implements authenticatorMakeCredential.
type MakeCredentialCommand struct {
	ClientDataHash        []byte
	RelyingParty          RelyingPartyEntity
	User                  UserEntity
	CredentialParameters  []CredentialParameter
	ExcludeList           []CredentialDescriptor
	Extensions            Extensions
	Options               *MakeCredentialOptions
	PinUVAuthParam        []byte
	PinUVAuthProtocol     uint64
	EnterpriseAttestation uint64
}

type makeCredentialRequest struct {
	ClientDataHash        []byte                 `cbor:"1,keyasint"`
	RelyingParty          RelyingPartyEntity     `cbor:"2,keyasint"`
	User                  UserEntity             `cbor:"3,keyasint"`
	CredentialParameters  []CredentialParameter  `cbor:"4,keyasint"`
	ExcludeList           []CredentialDescriptor `cbor:"5,keyasint,omitempty"`
	Extensions            Extensions             `cbor:"6,keyasint,omitempty"`
	Options               *MakeCredentialOptions `cbor:"7,keyasint,omitempty"`
	PinUVAuthParam        []byte                 `cbor:"8,keyasint,omitempty"`
	PinUVAuthProtocol     uint64                 `cbor:"9,keyasint,omitempty"`
	EnterpriseAttestation uint64                 `cbor:"10,keyasint,omitempty"`
}

// MakeCredentialResponse is the decoded response for authenticatorMakeCredential.
type MakeCredentialResponse struct {
	Format                string         `cbor:"1,keyasint"`
	AuthData              []byte         `cbor:"2,keyasint"`
	AttestationStatement  map[string]any `cbor:"3,keyasint"`
	EnterpriseAttestation bool           `cbor:"4,keyasint,omitempty"`
	LargeBlobKey          []byte         `cbor:"5,keyasint,omitempty"`
}

// NewMakeCredentialCommand creates a MakeCredential command instance.
func NewMakeCredentialCommand(clientDataHash []byte, relyingParty RelyingPartyEntity, user UserEntity, credentialParameters []CredentialParameter) *MakeCredentialCommand {
	return &MakeCredentialCommand{
		ClientDataHash:       append([]byte(nil), clientDataHash...),
		RelyingParty:         relyingParty,
		User:                 user,
		CredentialParameters: append([]CredentialParameter(nil), credentialParameters...),
	}
}

// Protocol returns the CTAP2 protocol family.
func (command *MakeCredentialCommand) Protocol() protocol.Family {
	return protocol.FamilyCTAP2
}

// Encode serializes the MakeCredential request.
func (command *MakeCredentialCommand) Encode() ([]byte, error) {
	if len(command.ClientDataHash) != 32 {
		return nil, fmt.Errorf("ctap2: make credential clientDataHash must be 32 bytes")
	}
	if command.RelyingParty.ID == "" {
		return nil, fmt.Errorf("ctap2: make credential rp.id is required")
	}
	if len(command.CredentialParameters) == 0 {
		return nil, fmt.Errorf("ctap2: make credential pubKeyCredParams is required")
	}

	request := makeCredentialRequest{
		ClientDataHash:        append([]byte(nil), command.ClientDataHash...),
		RelyingParty:          command.RelyingParty,
		User:                  command.User,
		CredentialParameters:  append([]CredentialParameter(nil), command.CredentialParameters...),
		ExcludeList:           append([]CredentialDescriptor(nil), command.ExcludeList...),
		Extensions:            command.Extensions,
		Options:               command.Options,
		PinUVAuthParam:        append([]byte(nil), command.PinUVAuthParam...),
		PinUVAuthProtocol:     command.PinUVAuthProtocol,
		EnterpriseAttestation: command.EnterpriseAttestation,
	}
	return encodeCommand(CommandMakeCredential, request)
}

// DecodeResponse parses the MakeCredential response structure.
func (command *MakeCredentialCommand) DecodeResponse(data []byte, response any) error {
	target, ok := response.(*MakeCredentialResponse)
	if !ok || target == nil {
		return fmt.Errorf("ctap2: make credential response target must be *MakeCredentialResponse")
	}
	if err := decodeCommandResponse(data, target); err != nil {
		return err
	}
	if target.Format == "" {
		return fmt.Errorf("ctap2: make credential response missing fmt")
	}
	if len(target.AuthData) == 0 {
		return fmt.Errorf("ctap2: make credential response missing authData")
	}
	if target.AttestationStatement == nil {
		return fmt.Errorf("ctap2: make credential response missing attStmt")
	}
	return nil
}
