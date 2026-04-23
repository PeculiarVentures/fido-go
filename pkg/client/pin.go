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

// SetPIN configures a new authenticator PIN using CTAP2 authenticatorClientPIN.
func (client *client) SetPIN(ctx context.Context, newPIN string) error {
	if newPIN == "" {
		return ErrNewPINRequired
	}

	caps, err := client.requireCTAP2Capabilities(ctx, "setting a PIN")
	if err != nil {
		return err
	}
	protocolVersion, err := selectPINUVAuthProtocol(caps.PinUVAuthProtocols)
	if err != nil {
		return err
	}
	session, err := client.getPINProtocol1Session(ctx, protocolVersion)
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

	command := ctap2.NewClientPINCommand(protocolVersion, ctap2.ClientPINSetPIN)
	command.KeyAgreement = session.keyAgreement
	command.NewPINEnc = newPINEnc
	command.PinUVAuthParam = pinProtocol1Authenticate(session.sharedSecret, newPINEnc)

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

// GetPINRetries returns the remaining ClientPIN retry counters for the authenticator.
func (client *client) GetPINRetries(ctx context.Context) (*PINRetries, error) {
	caps, err := client.requireCTAP2Capabilities(ctx, "reading PIN retry counters")
	if err != nil {
		return nil, err
	}
	if !caps.Options["clientPin"] {
		return nil, fmt.Errorf("client: authenticator does not have a PIN configured")
	}

	protocolVersion, err := selectPINUVAuthProtocol(caps.PinUVAuthProtocols)
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

	caps, err := client.requireCTAP2Capabilities(ctx, "changing the PIN")
	if err != nil {
		return err
	}
	if !caps.Options["clientPin"] {
		return fmt.Errorf("client: authenticator does not have a PIN configured")
	}

	protocolVersion, err := selectPINUVAuthProtocol(caps.PinUVAuthProtocols)
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

func (client *client) requireCTAP2Capabilities(ctx context.Context, operation string) (*ctap2.GetInfoResponse, error) {
	caps, err := client.GetCapabilities(ctx)
	if err != nil {
		return nil, err
	}
	if !caps.HasCTAP2() {
		if caps.HasCTAP1() {
			return nil, fmt.Errorf("client: authenticator supports CTAP1 only; %s requires CTAP2", operation)
		}
		return nil, ErrNoCapableProtocol
	}
	return caps.RawCTAP2, nil
}

func (client *client) resolveCTAP2UserVerification(ctx context.Context, info *ctap2.GetInfoResponse, operation string, selection AuthenticatorSelection, challengeHash []byte, permission ctap2.Permission, permissionsRPID string) (bool, []byte, uint64, error) {
	policy := selection.normalizedUserVerification()
	if policy == UserVerificationDiscouraged {
		return false, nil, 0, nil
	}
	if optionEnabled(info, "uv") {
		return true, nil, 0, nil
	}
	if !optionPresent(info, "clientPin") {
		if policy == UserVerificationRequired {
			return false, nil, 0, fmt.Errorf("client: authenticator does not support requested user verification")
		}
		return false, nil, 0, nil
	}

	pin, err := client.requestPIN(ctx, PINRequest{
		Operation: operation,
		Protocol:  FamilyCTAP2,
		Method:    VerificationMethodPIN,
		Message:   fmt.Sprintf("Enter the authenticator PIN to continue %s.", operation),
	})
	if err != nil {
		if err == ErrPINRequired && policy == UserVerificationPreferred {
			return false, nil, 0, nil
		}
		return false, nil, 0, err
	}

	pinToken, protocolVersion, err := client.pinTokenForPermission(ctx, info, pin, permission, permissionsRPID)
	if err != nil {
		return false, nil, 0, err
	}
	return false, pinProtocol1Authenticate(pinToken, challengeHash), protocolVersion, nil
}

func (client *client) pinTokenForPermission(ctx context.Context, info *ctap2.GetInfoResponse, pin string, permission ctap2.Permission, permissionsRPID string) ([]byte, uint64, error) {
	protocolVersion, err := selectPINUVAuthProtocol(info.PinUVAuthProtocols)
	if err != nil {
		return nil, 0, err
	}
	if optionEnabled(info, "pinUvAuthToken") {
		pinToken, err := client.getPINTokenWithPermissions(ctx, protocolVersion, pin, permission, permissionsRPID)
		if err != nil {
			return nil, 0, err
		}
		return pinToken, protocolVersion, nil
	}
	pinToken, err := client.getPINToken(ctx, protocolVersion, pin)
	if err != nil {
		return nil, 0, err
	}
	return pinToken, protocolVersion, nil
}
