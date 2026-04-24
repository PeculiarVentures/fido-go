package client

import (
	"context"
	"fmt"

	clientctap2 "github.com/PeculiarVentures/fido-go/internal/client/ctap2"
	"github.com/PeculiarVentures/fido-go/pkg/ctap2"
)

const clientPINPaddedLength = 64

// SetPIN configures a new authenticator PIN using CTAP2 authenticatorClientPIN.
func (client *client) SetPIN(ctx context.Context, newPIN Secret) error {
	if newPIN.Empty() {
		return ErrNewPINRequired
	}

	info, err := client.requireCTAP2Capabilities(ctx, "setting a PIN")
	if err != nil {
		return err
	}
	return client.ctap2Manager().SetPIN(ctx, info, newPIN)
}

// GetPINRetries returns the remaining ClientPIN retry counters for the authenticator.
func (client *client) GetPINRetries(ctx context.Context) (*PINRetries, error) {
	info, err := client.requireCTAP2Capabilities(ctx, "reading PIN retry counters")
	if err != nil {
		return nil, err
	}
	retries, err := client.ctap2Manager().GetPINRetries(ctx, info)
	if err != nil {
		return nil, err
	}
	return &PINRetries{
		PINRetries:      retries.PINRetries,
		UVRetries:       retries.UVRetries,
		PowerCycleState: retries.PowerCycleState,
	}, nil
}

// ChangePIN changes an existing authenticator PIN using CTAP2 authenticatorClientPIN.
func (client *client) ChangePIN(ctx context.Context, currentPIN Secret, newPIN Secret) error {
	if currentPIN.Empty() {
		return ErrPINRequired
	}
	if newPIN.Empty() {
		return ErrNewPINRequired
	}

	info, err := client.requireCTAP2Capabilities(ctx, "changing the PIN")
	if err != nil {
		return err
	}
	return client.ctap2Manager().ChangePIN(ctx, info, currentPIN, newPIN)
}

func (client *client) requireCTAP2Capabilities(ctx context.Context, operation string) (*ctap2.GetInfoResponse, error) {
	caps, err := client.Capabilities(ctx)
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
	defer wipeBytes(pinToken)
	return false, clientctap2.PinProtocolAuthenticate(protocolVersion, pinToken, challengeHash), protocolVersion, nil
}

func (client *client) pinTokenForPermission(ctx context.Context, info *ctap2.GetInfoResponse, pin Secret, permission ctap2.Permission, permissionsRPID string) ([]byte, uint64, error) {
	return client.ctap2Manager().PinTokenForPermission(ctx, info, pin, permission, permissionsRPID)
}
