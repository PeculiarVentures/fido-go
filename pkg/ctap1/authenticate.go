package ctap1

import (
	"encoding/binary"
	"fmt"

	"github.com/PeculiarVentures/fido-go/pkg/protocol"
)

// CommandAuthenticate is the CTAP1 Authenticate command identifier.
const CommandAuthenticate byte = 0x02

// Control identifies the CTAP1 authenticate control byte.
type Control byte

const (
	// ControlEnforceUserPresenceAndSign requires user presence before signing.
	ControlEnforceUserPresenceAndSign Control = 0x03
	// ControlCheckOnly checks whether a key handle matches this token/application.
	ControlCheckOnly Control = 0x07
	// ControlDontEnforceUserPresenceAndSign allows signing without user presence.
	ControlDontEnforceUserPresenceAndSign Control = 0x08
)

// AuthenticateResponse is the decoded response for U2F_AUTHENTICATE.
type AuthenticateResponse struct {
	UserPresence byte
	Counter      uint32
	Signature    []byte
}

// UserPresent reports whether the user-presence bit is set.
func (response AuthenticateResponse) UserPresent() bool {
	return response.UserPresence&0x01 == 0x01
}

// AuthenticateCommand implements U2F_AUTHENTICATE.
type AuthenticateCommand struct {
	Control     Control
	Challenge   []byte
	Application []byte
	KeyHandle   []byte
}

// NewAuthenticateCommand creates an Authenticate command instance.
func NewAuthenticateCommand(control Control, challenge, application, keyHandle []byte) *AuthenticateCommand {
	return &AuthenticateCommand{
		Control:     control,
		Challenge:   append([]byte(nil), challenge...),
		Application: append([]byte(nil), application...),
		KeyHandle:   append([]byte(nil), keyHandle...),
	}
}

// Protocol returns the CTAP1 protocol family.
func (command *AuthenticateCommand) Protocol() protocol.Family {
	return protocol.FamilyCTAP1
}

// Encode serializes the Authenticate command request.
func (command *AuthenticateCommand) Encode() ([]byte, error) {
	if err := command.Control.Validate(); err != nil {
		return nil, err
	}
	if len(command.Challenge) != 32 {
		return nil, fmt.Errorf("ctap1: authenticate challenge must be 32 bytes")
	}
	if len(command.Application) != 32 {
		return nil, fmt.Errorf("ctap1: authenticate application parameter must be 32 bytes")
	}
	if len(command.KeyHandle) == 0 {
		return nil, fmt.Errorf("ctap1: authenticate key handle must not be empty")
	}
	if len(command.KeyHandle) > 0xff {
		return nil, fmt.Errorf("ctap1: authenticate key handle exceeds 255 bytes")
	}

	payload := make([]byte, 0, 65+len(command.KeyHandle))
	payload = append(payload, command.Challenge...)
	payload = append(payload, command.Application...)
	payload = append(payload, byte(len(command.KeyHandle)))
	payload = append(payload, command.KeyHandle...)
	return encodeAPDU(CommandAuthenticate, byte(command.Control), 0x00, payload, maxExtendedResponseLength)
}

// DecodeResponse parses the Authenticate APDU response and extracts the structured payload.
func (command *AuthenticateCommand) DecodeResponse(data []byte, response any) error {
	target, ok := response.(*AuthenticateResponse)
	if !ok || target == nil {
		return fmt.Errorf("ctap1: authenticate response target must be *AuthenticateResponse")
	}

	payload, _, err := decodeResponse(data)
	if err != nil {
		return err
	}
	if len(payload) < 6 {
		return fmt.Errorf("ctap1: authenticate response payload is too short")
	}

	target.UserPresence = payload[0]
	target.Counter = binary.BigEndian.Uint32(payload[1:5])
	target.Signature = append([]byte(nil), payload[5:]...)
	if len(target.Signature) == 0 {
		return fmt.Errorf("ctap1: authenticate response missing signature")
	}
	return nil
}

// Validate reports whether the control byte is one of the allowed values.
func (control Control) Validate() error {
	switch control {
	case ControlEnforceUserPresenceAndSign, ControlCheckOnly, ControlDontEnforceUserPresenceAndSign:
		return nil
	default:
		return fmt.Errorf("ctap1: unsupported authenticate control byte 0x%02x", byte(control))
	}
}
