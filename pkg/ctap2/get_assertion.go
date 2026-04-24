package ctap2

import (
	"fmt"

	"github.com/PeculiarVentures/fido-go/pkg/protocol"
)

// CommandGetAssertion is the CTAP2 authenticatorGetAssertion command identifier.
const CommandGetAssertion byte = 0x02

// GetAssertionCommand implements authenticatorGetAssertion.
type GetAssertionCommand struct {
	RPID              string
	ClientDataHash    []byte
	AllowList         []CredentialDescriptor
	Extensions        Extensions
	Options           *GetAssertionOptions
	PinUVAuthParam    []byte
	PinUVAuthProtocol uint64
}

type getAssertionRequest struct {
	RPID              string                 `cbor:"1,keyasint"`
	ClientDataHash    []byte                 `cbor:"2,keyasint"`
	AllowList         []CredentialDescriptor `cbor:"3,keyasint,omitempty"`
	Extensions        Extensions             `cbor:"4,keyasint,omitempty"`
	Options           *GetAssertionOptions   `cbor:"5,keyasint,omitempty"`
	PinUVAuthParam    []byte                 `cbor:"6,keyasint,omitempty"`
	PinUVAuthProtocol uint64                 `cbor:"7,keyasint,omitempty"`
}

// GetAssertionResponse is the decoded response for authenticatorGetAssertion.
type GetAssertionResponse struct {
	Credential          CredentialDescriptor `cbor:"1,keyasint"`
	AuthData            []byte               `cbor:"2,keyasint"`
	Signature           []byte               `cbor:"3,keyasint"`
	User                *UserEntity          `cbor:"4,keyasint,omitempty"`
	NumberOfCredentials uint64               `cbor:"5,keyasint,omitempty"`
	UserSelected        bool                 `cbor:"6,keyasint,omitempty"`
	LargeBlobKey        []byte               `cbor:"7,keyasint,omitempty"`
}

// NewGetAssertionCommand creates a GetAssertion command instance.
func NewGetAssertionCommand(rpID string, clientDataHash []byte) *GetAssertionCommand {
	return &GetAssertionCommand{RPID: rpID, ClientDataHash: append([]byte(nil), clientDataHash...)}
}

// Protocol returns the CTAP2 protocol family.
func (command *GetAssertionCommand) Protocol() protocol.Family {
	return protocol.FamilyCTAP2
}

// Encode serializes the GetAssertion request.
func (command *GetAssertionCommand) Encode() ([]byte, error) {
	if command.RPID == "" {
		return nil, fmt.Errorf("ctap2: get assertion rpId is required")
	}
	if len(command.ClientDataHash) != 32 {
		return nil, fmt.Errorf("ctap2: get assertion clientDataHash must be 32 bytes")
	}

	request := getAssertionRequest{
		RPID:              command.RPID,
		ClientDataHash:    append([]byte(nil), command.ClientDataHash...),
		AllowList:         append([]CredentialDescriptor(nil), command.AllowList...),
		Extensions:        command.Extensions,
		Options:           command.Options,
		PinUVAuthParam:    append([]byte(nil), command.PinUVAuthParam...),
		PinUVAuthProtocol: command.PinUVAuthProtocol,
	}
	return encodeCommand(CommandGetAssertion, request)
}

// DecodeResponse parses the GetAssertion response structure.
func (command *GetAssertionCommand) DecodeResponse(data []byte, response any) error {
	target, err := DecodeInto[GetAssertionResponse](response, "get assertion")
	if err != nil {
		return err
	}
	if err := decodeCommandResponse(data, target); err != nil {
		return err
	}
	if len(target.Credential.ID) == 0 {
		return fmt.Errorf("ctap2: get assertion response missing credential id")
	}
	if len(target.AuthData) == 0 {
		return fmt.Errorf("ctap2: get assertion response missing authData")
	}
	if len(target.Signature) == 0 {
		return fmt.Errorf("ctap2: get assertion response missing signature")
	}
	return nil
}
