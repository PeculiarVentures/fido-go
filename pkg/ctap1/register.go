package ctap1

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"

	"github.com/PeculiarVentures/fido-go/pkg/protocol"
)

// CommandRegister is the CTAP1 Register command identifier.
const CommandRegister byte = 0x01

// RegisterResponse is the decoded response for U2F_REGISTER.
type RegisterResponse struct {
	ReservedByte           byte
	PublicKey              []byte
	KeyHandle              []byte
	AttestationCertificate []byte
	Signature              []byte
}

// RegisterCommand implements U2F_REGISTER.
type RegisterCommand struct {
	Challenge   []byte
	Application []byte
}

// NewRegisterCommand creates a Register command instance.
func NewRegisterCommand(challenge, application []byte) *RegisterCommand {
	return &RegisterCommand{
		Challenge:   append([]byte(nil), challenge...),
		Application: append([]byte(nil), application...),
	}
}

// Protocol returns the CTAP1 protocol family.
func (command *RegisterCommand) Protocol() protocol.Family {
	return protocol.FamilyCTAP1
}

// Encode serializes the Register command request.
func (command *RegisterCommand) Encode() ([]byte, error) {
	if len(command.Challenge) != 32 {
		return nil, fmt.Errorf("ctap1: register challenge must be 32 bytes")
	}
	if len(command.Application) != 32 {
		return nil, fmt.Errorf("ctap1: register application parameter must be 32 bytes")
	}

	payload := make([]byte, 0, 64)
	payload = append(payload, command.Challenge...)
	payload = append(payload, command.Application...)
	return encodeAPDU(CommandRegister, 0x00, 0x00, payload, maxExtendedResponseLength)
}

// DecodeResponse parses the Register APDU response and extracts the structured payload.
func (command *RegisterCommand) DecodeResponse(data []byte, response any) error {
	target, ok := response.(*RegisterResponse)
	if !ok || target == nil {
		return fmt.Errorf("ctap1: register response target must be *RegisterResponse")
	}

	payload, _, err := decodeResponse(data)
	if err != nil {
		return err
	}
	if len(payload) < 67 {
		return fmt.Errorf("ctap1: register response payload is too short")
	}
	if payload[0] != 0x05 {
		return fmt.Errorf("ctap1: register response reserved byte must be 0x05")
	}

	keyHandleLength := int(payload[66])
	keyHandleOffset := 67
	if len(payload) < keyHandleOffset+keyHandleLength {
		return fmt.Errorf("ctap1: register response key handle is truncated")
	}

	remaining := payload[keyHandleOffset+keyHandleLength:]
	if len(remaining) == 0 {
		return fmt.Errorf("ctap1: register response missing attestation certificate")
	}

	var certificate asn1.RawValue
	rest, err := asn1.Unmarshal(remaining, &certificate)
	if err != nil {
		return fmt.Errorf("ctap1: parse attestation certificate: %w", err)
	}
	certificateLength := len(remaining) - len(rest)
	if certificateLength == 0 {
		return fmt.Errorf("ctap1: register response missing certificate bytes")
	}
	certificateBytes := remaining[:certificateLength]
	if _, err := x509.ParseCertificate(certificateBytes); err != nil {
		return fmt.Errorf("ctap1: parse attestation certificate: %w", err)
	}
	if len(rest) == 0 {
		return fmt.Errorf("ctap1: register response missing signature bytes")
	}

	target.ReservedByte = payload[0]
	target.PublicKey = append([]byte(nil), payload[1:66]...)
	target.KeyHandle = append([]byte(nil), payload[keyHandleOffset:keyHandleOffset+keyHandleLength]...)
	target.AttestationCertificate = append([]byte(nil), certificateBytes...)
	target.Signature = append([]byte(nil), rest...)
	return nil
}
