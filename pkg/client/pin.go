package client

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/PeculiarVentures/fido-go/pkg/ctap2"
	"github.com/PeculiarVentures/fido-go/pkg/protocol"
)

const clientPINPaddedLength = 64
const clientPINChangeAttempts = 3

// GetPINRetries returns the remaining ClientPIN retry counters for the authenticator.
func (client *client) GetPINRetries(ctx context.Context) (*PINRetries, error) {
	caps, err := client.GetCapabilities(ctx)
	if err != nil {
		return nil, err
	}
	if !caps.HasCTAP2() {
		return nil, ErrNoCapableProtocol
	}
	if !caps.CTAP2.Options["clientPin"] {
		return nil, fmt.Errorf("client: authenticator does not support client PIN")
	}

	protocolVersion, err := selectPINUVAuthProtocol(caps.CTAP2.PinUVAuthProtocols)
	if err != nil {
		return nil, err
	}

	command := ctap2.NewClientPINGetRetriesCommand(protocolVersion)
	encoded, err := command.Encode()
	if err != nil {
		return nil, err
	}
	responseBytes, err := client.InvokeRaw(ctx, protocol.FamilyCTAP2, ctap2.CommandClientPIN, encoded[1:])
	if err != nil {
		return nil, err
	}
	var response ctap2.ClientPINResponse
	if err := command.DecodeResponse(responseBytes, &response); err != nil {
		return nil, err
	}
	return &PINRetries{
		PINRetries:      response.PINRetries,
		UVRetries:       response.UVRetries,
		PowerCycleState: response.PowerCycleState,
	}, nil
}

// ChangePIN changes an existing authenticator PIN using CTAP2 authenticatorClientPIN.
func (client *client) ChangePIN(ctx context.Context, currentPIN string, newPIN string) error {
	var err error
	for attempt := 0; attempt < clientPINChangeAttempts; attempt++ {
		err = client.changePINOnce(ctx, currentPIN, newPIN)
		if !shouldRetryClientPINChange(err) {
			return err
		}
	}
	return err
}

func (client *client) changePINOnce(ctx context.Context, currentPIN string, newPIN string) error {
	if currentPIN == "" {
		return ErrPINRequired
	}
	if newPIN == "" {
		return ErrNewPINRequired
	}

	caps, err := client.GetCapabilities(ctx)
	if err != nil {
		return err
	}
	if !caps.HasCTAP2() {
		return ErrNoCapableProtocol
	}
	if !caps.CTAP2.Options["clientPin"] {
		return fmt.Errorf("client: authenticator does not support client PIN")
	}

	protocolVersion, err := selectPINUVAuthProtocol(caps.CTAP2.PinUVAuthProtocols)
	if err != nil {
		return err
	}
	session, err := client.getPINProtocol1Session(ctx, protocolVersion)
	if err != nil {
		return err
	}

	currentPINHash := sha256.Sum256([]byte(currentPIN))
	pinHashEnc, err := pinProtocol1Encrypt(session.sharedSecret, currentPINHash[:16])
	if err != nil {
		return err
	}
	paddedNewPIN, err := padClientPIN(newPIN)
	if err != nil {
		return err
	}
	newPINEnc, err := pinProtocol1Encrypt(session.sharedSecret, paddedNewPIN)
	if err != nil {
		return err
	}
	authMessage := make([]byte, 0, len(newPINEnc)+len(pinHashEnc))
	authMessage = append(authMessage, newPINEnc...)
	authMessage = append(authMessage, pinHashEnc...)

	command := ctap2.NewClientPINCommand(protocolVersion, ctap2.ClientPINChangePIN)
	command.KeyAgreement = session.keyAgreement
	command.PINHashEnc = pinHashEnc
	command.NewPINEnc = newPINEnc
	command.PinUVAuthParam = pinProtocol1Authenticate(session.sharedSecret, authMessage)

	encoded, err := command.Encode()
	if err != nil {
		return err
	}
	responseBytes, err := client.InvokeRaw(ctx, protocol.FamilyCTAP2, ctap2.CommandClientPIN, encoded[1:])
	if err != nil {
		return err
	}
	var response ctap2.ClientPINResponse
	return command.DecodeResponse(responseBytes, &response)
}

func shouldRetryClientPINChange(err error) bool {
	var statusErr *ctap2.Error
	if !errors.As(err, &statusErr) {
		return false
	}
	return statusErr.Code == 0x12
}

func padClientPIN(pin string) ([]byte, error) {
	pinBytes := []byte(pin)
	if len(pinBytes) == 0 {
		return nil, ErrNewPINRequired
	}
	if len(pinBytes) > clientPINPaddedLength-1 {
		return nil, fmt.Errorf("client: pin length %d exceeds %d bytes", len(pinBytes), clientPINPaddedLength-1)
	}
	padded := make([]byte, clientPINPaddedLength)
	copy(padded, pinBytes)
	return padded, nil
}
