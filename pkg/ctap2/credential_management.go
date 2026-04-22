package ctap2

import (
	"fmt"

	"github.com/PeculiarVentures/fido-go/pkg/protocol"
	"github.com/fxamacker/cbor/v2"
)

// CommandCredentialManagement is the CTAP2 authenticatorCredentialManagement command identifier.
const CommandCredentialManagement byte = 0x0a

// CommandCredentialManagementPreview is the CTAP2 preview credential-management command identifier.
const CommandCredentialManagementPreview byte = 0x41

// CredentialManagementSubcommand identifies one credential-management operation.
type CredentialManagementSubcommand uint64

const (
	// CredentialManagementGetMetadata returns resident-credential capacity metadata.
	CredentialManagementGetMetadata CredentialManagementSubcommand = 0x01
	// CredentialManagementEnumerateRPsBegin starts relying-party enumeration.
	CredentialManagementEnumerateRPsBegin CredentialManagementSubcommand = 0x02
	// CredentialManagementEnumerateRPsGetNext advances relying-party enumeration.
	CredentialManagementEnumerateRPsGetNext CredentialManagementSubcommand = 0x03
	// CredentialManagementEnumerateCredentialsBegin starts credential enumeration for one RP.
	CredentialManagementEnumerateCredentialsBegin CredentialManagementSubcommand = 0x04
	// CredentialManagementEnumerateCredentialsGetNext advances credential enumeration.
	CredentialManagementEnumerateCredentialsGetNext CredentialManagementSubcommand = 0x05
	// CredentialManagementDeleteCredential deletes one discoverable credential.
	CredentialManagementDeleteCredential CredentialManagementSubcommand = 0x06
	// CredentialManagementUpdateUserInformation updates the stored user entity.
	CredentialManagementUpdateUserInformation CredentialManagementSubcommand = 0x07
)

// CredentialManagementSubcommandParams contains the supported subcommand parameter keys.
type CredentialManagementSubcommandParams struct {
	RPIDHash     []byte                `cbor:"1,keyasint,omitempty"`
	CredentialID *CredentialDescriptor `cbor:"2,keyasint,omitempty"`
	User         *UserEntity           `cbor:"3,keyasint,omitempty"`
}

// CredentialManagementCommand implements authenticatorCredentialManagement foundations.
type CredentialManagementCommand struct {
	CommandCode       byte
	Subcommand        CredentialManagementSubcommand
	SubcommandParams  *CredentialManagementSubcommandParams
	PinUVAuthProtocol uint64
	PinUVAuthParam    []byte
}

type credentialManagementRequest struct {
	Subcommand        CredentialManagementSubcommand        `cbor:"1,keyasint"`
	SubcommandParams  *CredentialManagementSubcommandParams `cbor:"2,keyasint,omitempty"`
	PinUVAuthProtocol uint64                                `cbor:"3,keyasint,omitempty"`
	PinUVAuthParam    []byte                                `cbor:"4,keyasint,omitempty"`
}

// CredentialManagementResponse is the decoded response for authenticatorCredentialManagement.
type CredentialManagementResponse struct {
	ExistingResidentCredentialsCount             uint64                `cbor:"1,keyasint,omitempty"`
	MaxPossibleRemainingResidentCredentialsCount uint64                `cbor:"2,keyasint,omitempty"`
	RP                                           *RelyingPartyEntity   `cbor:"3,keyasint,omitempty"`
	RPIDHash                                     []byte                `cbor:"4,keyasint,omitempty"`
	TotalRPs                                     uint64                `cbor:"5,keyasint,omitempty"`
	User                                         *UserEntity           `cbor:"6,keyasint,omitempty"`
	CredentialID                                 *CredentialDescriptor `cbor:"7,keyasint,omitempty"`
	PublicKey                                    map[int64]any         `cbor:"8,keyasint,omitempty"`
	TotalCredentials                             uint64                `cbor:"9,keyasint,omitempty"`
	CredProtect                                  uint64                `cbor:"10,keyasint,omitempty"`
	LargeBlobKey                                 []byte                `cbor:"11,keyasint,omitempty"`
}

// NewCredentialManagementCommand creates a credential-management command instance.
func NewCredentialManagementCommand(commandCode byte, subcommand CredentialManagementSubcommand) *CredentialManagementCommand {
	if commandCode == 0 {
		commandCode = CommandCredentialManagement
	}
	return &CredentialManagementCommand{CommandCode: commandCode, Subcommand: subcommand}
}

// Protocol returns the CTAP2 protocol family.
func (command *CredentialManagementCommand) Protocol() protocol.Family {
	return protocol.FamilyCTAP2
}

// CommandByte returns the encoded CTAP2 command byte.
func (command *CredentialManagementCommand) CommandByte() byte {
	if command.CommandCode == 0 {
		return CommandCredentialManagement
	}
	return command.CommandCode
}

// AuthenticationMessage returns the pinUvAuth message for this subcommand.
func (command *CredentialManagementCommand) AuthenticationMessage() ([]byte, error) {
	if command.Subcommand == 0 {
		return nil, fmt.Errorf("ctap2: credential management subcommand is required")
	}
	message := []byte{byte(command.Subcommand)}
	encodedParams, err := command.encodedSubcommandParams()
	if err != nil {
		return nil, err
	}
	return append(message, encodedParams...), nil
}

// Encode serializes the credential-management request.
func (command *CredentialManagementCommand) Encode() ([]byte, error) {
	if command.Subcommand == 0 {
		return nil, fmt.Errorf("ctap2: credential management subcommand is required")
	}

	request := credentialManagementRequest{
		Subcommand:        command.Subcommand,
		SubcommandParams:  command.SubcommandParams,
		PinUVAuthProtocol: command.PinUVAuthProtocol,
		PinUVAuthParam:    append([]byte(nil), command.PinUVAuthParam...),
	}
	return encodeCommand(command.CommandByte(), request)
}

// DecodeResponse parses the credential-management response structure.
func (command *CredentialManagementCommand) DecodeResponse(data []byte, response any) error {
	target, ok := response.(*CredentialManagementResponse)
	if !ok || target == nil {
		return fmt.Errorf("ctap2: credential management response target must be *CredentialManagementResponse")
	}
	return decodeCommandResponse(data, target)
}

func (command *CredentialManagementCommand) encodedSubcommandParams() ([]byte, error) {
	if command.SubcommandParams == nil {
		return nil, nil
	}
	encoded, err := cbor.Marshal(command.SubcommandParams)
	if err != nil {
		return nil, fmt.Errorf("ctap2: encode credential management params: %w", err)
	}
	return encoded, nil
}
