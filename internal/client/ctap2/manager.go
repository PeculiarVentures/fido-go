package clientctap2

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/PeculiarVentures/fido-go/pkg/ctap2"
)

const clientPINPaddedLength = 64
const clientPINChangeAttempts = 3

// Manager executes CTAP2 PIN and credential-management operations behind the public facade.
type Manager struct {
	invoker Invoker
}

// New constructs a CTAP2 internal manager over a raw command invoker.
func New(invoker Invoker) Manager {
	return Manager{invoker: invoker}
}

// DiscoverableCredential describes one resident credential returned by credential management.
type DiscoverableCredential struct {
	RP           ctap2.RelyingPartyEntity
	RPIDHash     []byte
	User         ctap2.UserEntity
	Credential   ctap2.CredentialDescriptor
	CredProtect  uint64
	LargeBlobKey []byte
}

// CredentialListResult contains credential-management metadata and enumerated credentials.
type CredentialListResult struct {
	ExistingResidentCredentialsCount             uint64
	MaxPossibleRemainingResidentCredentialsCount uint64
	Credentials                                  []DiscoverableCredential
}

// PINRetries describes the authenticator retry counters reported by ClientPIN.
type PINRetries struct {
	PINRetries      uint64
	UVRetries       uint64
	PowerCycleState bool
}

type credentialManagementTokenSource struct {
	token                  func(ctx context.Context, commandCode byte, protocolVersion uint64) ([]byte, error)
	supportsPreviewCommand bool
}

type relyingPartyCredentialSet struct {
	RP       ctap2.RelyingPartyEntity
	RPIDHash []byte
}

// ListCredentials enumerates discoverable credentials using CTAP2 credential management.
func (manager Manager) ListCredentials(ctx context.Context, info *ctap2.GetInfoResponse, pin []byte) (*CredentialListResult, error) {
	return manager.listCredentials(ctx, info, manager.pinCredentialManagementTokenSource(pin))
}

// ListCredentialsWithBuiltInUV enumerates discoverable credentials using authenticator-side UV.
func (manager Manager) ListCredentialsWithBuiltInUV(ctx context.Context, info *ctap2.GetInfoResponse) (*CredentialListResult, error) {
	return manager.listCredentials(ctx, info, manager.builtInUVCredentialManagementTokenSource())
}

func (manager Manager) listCredentials(ctx context.Context, info *ctap2.GetInfoResponse, tokenSource credentialManagementTokenSource) (*CredentialListResult, error) {
	commandCode, err := credentialManagementCommandCode(info)
	if err != nil {
		return nil, err
	}
	protocolVersion, err := SelectPINUVAuthProtocol(info.PinUVAuthProtocols)
	if err != nil {
		return nil, err
	}
	result, err := manager.listCredentialsWithCommand(ctx, commandCode, protocolVersion, tokenSource)
	if err == nil {
		return result, nil
	}
	if shouldRetryCredentialManagement(err) {
		retried, retryErr := manager.listCredentialsWithCommand(ctx, commandCode, protocolVersion, tokenSource)
		if retryErr == nil {
			return retried, nil
		}
		err = retryErr
	}
	if commandCode == ctap2.CommandCredentialManagement && tokenSource.supportsPreviewCommand && shouldRetryCredentialManagementWithPreview(info, err) {
		return manager.listCredentialsWithCommand(ctx, ctap2.CommandCredentialManagementPreview, protocolVersion, tokenSource)
	}
	return nil, err
}

// DeleteCredential removes one discoverable credential using CTAP2 credential management.
func (manager Manager) DeleteCredential(ctx context.Context, info *ctap2.GetInfoResponse, credential ctap2.CredentialDescriptor, pin []byte) error {
	return manager.deleteCredential(ctx, info, credential, manager.pinCredentialManagementTokenSource(pin))
}

// DeleteCredentialWithBuiltInUV removes one discoverable credential using authenticator-side UV.
func (manager Manager) DeleteCredentialWithBuiltInUV(ctx context.Context, info *ctap2.GetInfoResponse, credential ctap2.CredentialDescriptor) error {
	return manager.deleteCredential(ctx, info, credential, manager.builtInUVCredentialManagementTokenSource())
}

func (manager Manager) deleteCredential(ctx context.Context, info *ctap2.GetInfoResponse, credential ctap2.CredentialDescriptor, tokenSource credentialManagementTokenSource) error {
	commandCode, err := credentialManagementCommandCode(info)
	if err != nil {
		return err
	}
	protocolVersion, err := SelectPINUVAuthProtocol(info.PinUVAuthProtocols)
	if err != nil {
		return err
	}
	err = manager.deleteCredentialWithCommand(ctx, commandCode, protocolVersion, credential, tokenSource)
	if err == nil {
		return nil
	}
	if shouldRetryCredentialManagement(err) {
		retryErr := manager.deleteCredentialWithCommand(ctx, commandCode, protocolVersion, credential, tokenSource)
		if retryErr == nil {
			return nil
		}
		err = retryErr
	}
	if commandCode == ctap2.CommandCredentialManagement && tokenSource.supportsPreviewCommand && shouldRetryCredentialManagementWithPreview(info, err) {
		return manager.deleteCredentialWithCommand(ctx, ctap2.CommandCredentialManagementPreview, protocolVersion, credential, tokenSource)
	}
	return err
}

// SetPIN configures a new authenticator PIN using CTAP2 authenticatorClientPIN.
func (manager Manager) SetPIN(ctx context.Context, info *ctap2.GetInfoResponse, newPIN []byte) error {
	protocolVersion, err := SelectPINUVAuthProtocol(info.PinUVAuthProtocols)
	if err != nil {
		return err
	}
	session, err := manager.getPINProtocolSession(ctx, protocolVersion)
	if err != nil {
		return err
	}
	paddedNewPIN, err := padClientPIN(newPIN)
	if err != nil {
		return err
	}
	defer wipeBytes(paddedNewPIN)
	newPINEnc, err := pinProtocolEncrypt(session.version, session.sharedSecret, paddedNewPIN)
	if err != nil {
		return err
	}

	command := ctap2.NewClientPINCommand(protocolVersion, ctap2.ClientPINSetPIN)
	command.KeyAgreement = session.keyAgreement
	command.NewPINEnc = newPINEnc
	command.PinUVAuthParam = PinProtocolAuthenticate(session.version, session.sharedSecret, newPINEnc)

	encoded, err := command.Encode()
	if err != nil {
		return err
	}
	responseBytes, err := manager.invoker.InvokeCTAP2(ctx, ctap2.CommandClientPIN, encoded[1:])
	if err != nil {
		return err
	}
	var response ctap2.ClientPINResponse
	return command.DecodeResponse(responseBytes, &response)
}

// GetPINRetries returns the remaining ClientPIN retry counters for the authenticator.
func (manager Manager) GetPINRetries(ctx context.Context, info *ctap2.GetInfoResponse) (*PINRetries, error) {
	if !optionEnabled(info, "clientPin") {
		return nil, fmt.Errorf("client: authenticator does not have a PIN configured")
	}
	protocolVersion, err := SelectPINUVAuthProtocol(info.PinUVAuthProtocols)
	if err != nil {
		return nil, err
	}
	command := ctap2.NewClientPINGetRetriesCommand(protocolVersion)
	encoded, err := command.Encode()
	if err != nil {
		return nil, err
	}
	responseBytes, err := manager.invoker.InvokeCTAP2(ctx, ctap2.CommandClientPIN, encoded[1:])
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
func (manager Manager) ChangePIN(ctx context.Context, info *ctap2.GetInfoResponse, currentPIN []byte, newPIN []byte) error {
	var err error
	for attempt := 0; attempt < clientPINChangeAttempts; attempt++ {
		err = manager.changePINOnce(ctx, info, currentPIN, newPIN)
		if !shouldRetryClientPINChange(err) {
			return err
		}
	}
	return err
}

// PinTokenForPermission resolves a pinUvAuthToken and protocol version for a specific permission.
func (manager Manager) PinTokenForPermission(ctx context.Context, info *ctap2.GetInfoResponse, pin []byte, permission ctap2.Permission, permissionsRPID string) ([]byte, uint64, error) {
	protocolVersion, err := SelectPINUVAuthProtocol(info.PinUVAuthProtocols)
	if err != nil {
		return nil, 0, err
	}
	if optionEnabled(info, "pinUvAuthToken") {
		pinToken, err := manager.getPINTokenWithPermissions(ctx, protocolVersion, pin, permission, permissionsRPID)
		if err != nil {
			return nil, 0, err
		}
		return pinToken, protocolVersion, nil
	}
	pinToken, err := manager.getPINToken(ctx, protocolVersion, pin)
	if err != nil {
		return nil, 0, err
	}
	return pinToken, protocolVersion, nil
}

// NormalizeCredentialDescriptor clones and normalizes a credential descriptor.
func NormalizeCredentialDescriptor(credential ctap2.CredentialDescriptor) (ctap2.CredentialDescriptor, error) {
	if len(credential.ID) == 0 {
		return ctap2.CredentialDescriptor{}, fmt.Errorf("client: credential id is required")
	}
	normalized := ctap2.CredentialDescriptor{
		Type:       credential.Type,
		ID:         append([]byte(nil), credential.ID...),
		Transports: append([]ctap2.AuthenticatorTransport(nil), credential.Transports...),
	}
	if normalized.Type == "" {
		normalized.Type = "public-key"
	}
	return normalized, nil
}

func (manager Manager) listCredentialsWithCommand(ctx context.Context, commandCode byte, protocolVersion uint64, tokenSource credentialManagementTokenSource) (*CredentialListResult, error) {
	pinToken, err := tokenSource.token(ctx, commandCode, protocolVersion)
	if err != nil {
		return nil, err
	}
	defer wipeBytes(pinToken)

	result, err := manager.getCredentialMetadata(ctx, commandCode, protocolVersion, pinToken)
	if err != nil {
		return nil, err
	}
	if result.ExistingResidentCredentialsCount == 0 {
		return result, nil
	}

	relyingParties, err := manager.enumerateRelyingParties(ctx, commandCode, protocolVersion, pinToken)
	if err != nil {
		return nil, err
	}
	for _, relyingParty := range relyingParties {
		credentials, err := manager.enumerateCredentials(ctx, commandCode, protocolVersion, pinToken, relyingParty)
		if err != nil {
			return nil, err
		}
		result.Credentials = append(result.Credentials, credentials...)
	}
	return result, nil
}

func (manager Manager) getCredentialManagementPINToken(ctx context.Context, commandCode byte, protocolVersion uint64, pin []byte) ([]byte, error) {
	if commandCode == ctap2.CommandCredentialManagementPreview {
		return manager.getPINToken(ctx, protocolVersion, pin)
	}
	return manager.getPINTokenWithPermissions(ctx, protocolVersion, pin, ctap2.PermissionCredentialManagement, "")
}

func (manager Manager) getCredentialManagementUVToken(ctx context.Context, _ byte, protocolVersion uint64) ([]byte, error) {
	return manager.getUVTokenWithPermissions(ctx, protocolVersion, ctap2.PermissionCredentialManagement, "")
}

func (manager Manager) pinCredentialManagementTokenSource(pin []byte) credentialManagementTokenSource {
	return credentialManagementTokenSource{
		token: func(ctx context.Context, commandCode byte, protocolVersion uint64) ([]byte, error) {
			return manager.getCredentialManagementPINToken(ctx, commandCode, protocolVersion, pin)
		},
		supportsPreviewCommand: true,
	}
}

func (manager Manager) builtInUVCredentialManagementTokenSource() credentialManagementTokenSource {
	return credentialManagementTokenSource{token: manager.getCredentialManagementUVToken}
}

func (manager Manager) getCredentialMetadata(ctx context.Context, commandCode byte, protocolVersion uint64, pinToken []byte) (*CredentialListResult, error) {
	command := ctap2.NewCredentialManagementCommand(commandCode, ctap2.CredentialManagementGetMetadata)
	command.PinUVAuthProtocol = protocolVersion
	pinUVAuthParam, err := PinProtocolAuthParam(protocolVersion, pinToken, command)
	if err != nil {
		return nil, err
	}
	command.PinUVAuthParam = pinUVAuthParam

	response, err := manager.invokeCredentialManagement(ctx, command)
	if err != nil {
		return nil, err
	}
	return &CredentialListResult{
		ExistingResidentCredentialsCount:             response.ExistingResidentCredentialsCount,
		MaxPossibleRemainingResidentCredentialsCount: response.MaxPossibleRemainingResidentCredentialsCount,
	}, nil
}

func (manager Manager) enumerateRelyingParties(ctx context.Context, commandCode byte, protocolVersion uint64, pinToken []byte) ([]relyingPartyCredentialSet, error) {
	command := ctap2.NewCredentialManagementCommand(commandCode, ctap2.CredentialManagementEnumerateRPsBegin)
	command.PinUVAuthProtocol = protocolVersion
	pinUVAuthParam, err := PinProtocolAuthParam(protocolVersion, pinToken, command)
	if err != nil {
		return nil, err
	}
	command.PinUVAuthParam = pinUVAuthParam

	response, err := manager.invokeCredentialManagement(ctx, command)
	if err != nil {
		return nil, err
	}
	if response.RP == nil {
		return nil, nil
	}

	result := []relyingPartyCredentialSet{{
		RP:       *response.RP,
		RPIDHash: append([]byte(nil), response.RPIDHash...),
	}}
	totalRPs := response.TotalRPs
	if totalRPs == 0 {
		totalRPs = 1
	}
	for uint64(len(result)) < totalRPs {
		nextCommand := ctap2.NewCredentialManagementCommand(commandCode, ctap2.CredentialManagementEnumerateRPsGetNext)
		nextResponse, err := manager.invokeCredentialManagement(ctx, nextCommand)
		if err != nil {
			return nil, err
		}
		if nextResponse.RP == nil {
			return nil, fmt.Errorf("client: credential management response missing relying party")
		}
		result = append(result, relyingPartyCredentialSet{
			RP:       *nextResponse.RP,
			RPIDHash: append([]byte(nil), nextResponse.RPIDHash...),
		})
	}
	return result, nil
}

func (manager Manager) enumerateCredentials(ctx context.Context, commandCode byte, protocolVersion uint64, pinToken []byte, relyingParty relyingPartyCredentialSet) ([]DiscoverableCredential, error) {
	command := ctap2.NewCredentialManagementCommand(commandCode, ctap2.CredentialManagementEnumerateCredentialsBegin)
	command.SubcommandParams = &ctap2.CredentialManagementSubcommandParams{RPIDHash: append([]byte(nil), relyingParty.RPIDHash...)}
	command.PinUVAuthProtocol = protocolVersion
	pinUVAuthParam, err := PinProtocolAuthParam(protocolVersion, pinToken, command)
	if err != nil {
		return nil, err
	}
	command.PinUVAuthParam = pinUVAuthParam

	response, err := manager.invokeCredentialManagement(ctx, command)
	if err != nil {
		return nil, err
	}
	credential, err := discoverableCredentialFromResponse(relyingParty, response)
	if err != nil {
		return nil, err
	}
	result := []DiscoverableCredential{credential}
	totalCredentials := response.TotalCredentials
	if totalCredentials == 0 {
		totalCredentials = 1
	}
	for uint64(len(result)) < totalCredentials {
		nextCommand := ctap2.NewCredentialManagementCommand(commandCode, ctap2.CredentialManagementEnumerateCredentialsGetNext)
		nextResponse, err := manager.invokeCredentialManagement(ctx, nextCommand)
		if err != nil {
			return nil, err
		}
		credential, err := discoverableCredentialFromResponse(relyingParty, nextResponse)
		if err != nil {
			return nil, err
		}
		result = append(result, credential)
	}
	return result, nil
}

func (manager Manager) deleteCredentialWithCommand(ctx context.Context, commandCode byte, protocolVersion uint64, credential ctap2.CredentialDescriptor, tokenSource credentialManagementTokenSource) error {
	pinToken, err := tokenSource.token(ctx, commandCode, protocolVersion)
	if err != nil {
		return err
	}
	defer wipeBytes(pinToken)

	command := ctap2.NewCredentialManagementCommand(commandCode, ctap2.CredentialManagementDeleteCredential)
	command.SubcommandParams = &ctap2.CredentialManagementSubcommandParams{CredentialID: &credential}
	command.PinUVAuthProtocol = protocolVersion
	pinUVAuthParam, err := PinProtocolAuthParam(protocolVersion, pinToken, command)
	if err != nil {
		return err
	}
	command.PinUVAuthParam = pinUVAuthParam

	_, err = manager.invokeCredentialManagement(ctx, command)
	return err
}

func (manager Manager) getPINTokenWithPermissions(ctx context.Context, protocolVersion uint64, pin []byte, permissions ctap2.Permission, permissionsRPID string) ([]byte, error) {
	session, err := manager.getPINProtocolSession(ctx, protocolVersion)
	if err != nil {
		return nil, err
	}
	pinHash := sha256.Sum256(pin)
	pinHashEnc, err := pinProtocolEncrypt(session.version, session.sharedSecret, pinHash[:16])
	if err != nil {
		return nil, err
	}

	command := ctap2.NewClientPINCommand(protocolVersion, ctap2.ClientPINGetPINTokenWithPIN)
	command.KeyAgreement = session.keyAgreement
	command.PINHashEnc = pinHashEnc
	command.Permissions = permissions
	command.PermissionsRPID = permissionsRPID

	encoded, err := command.Encode()
	if err != nil {
		return nil, err
	}
	responseBytes, err := manager.invoker.InvokeCTAP2(ctx, ctap2.CommandClientPIN, encoded[1:])
	if err != nil {
		return nil, err
	}
	var response ctap2.ClientPINResponse
	if err := command.DecodeResponse(responseBytes, &response); err != nil {
		return nil, err
	}
	if len(response.PinUVAuthToken) == 0 {
		return nil, fmt.Errorf("client: authenticator did not return pinUvAuthToken")
	}
	return pinProtocolDecrypt(session.version, session.sharedSecret, response.PinUVAuthToken)
}

func (manager Manager) getUVTokenWithPermissions(ctx context.Context, protocolVersion uint64, permissions ctap2.Permission, permissionsRPID string) ([]byte, error) {
	session, err := manager.getPINProtocolSession(ctx, protocolVersion)
	if err != nil {
		return nil, err
	}

	command := ctap2.NewClientPINCommand(protocolVersion, ctap2.ClientPINGetPINTokenWithUV)
	command.KeyAgreement = session.keyAgreement
	command.Permissions = permissions
	command.PermissionsRPID = permissionsRPID

	encoded, err := command.Encode()
	if err != nil {
		return nil, err
	}
	responseBytes, err := manager.invoker.InvokeCTAP2(ctx, ctap2.CommandClientPIN, encoded[1:])
	if err != nil {
		return nil, err
	}
	var response ctap2.ClientPINResponse
	if err := command.DecodeResponse(responseBytes, &response); err != nil {
		return nil, err
	}
	if len(response.PinUVAuthToken) == 0 {
		return nil, fmt.Errorf("client: authenticator did not return pinUvAuthToken")
	}
	return pinProtocolDecrypt(session.version, session.sharedSecret, response.PinUVAuthToken)
}

func (manager Manager) getPINToken(ctx context.Context, protocolVersion uint64, pin []byte) ([]byte, error) {
	session, err := manager.getPINProtocolSession(ctx, protocolVersion)
	if err != nil {
		return nil, err
	}
	pinHash := sha256.Sum256(pin)
	pinHashEnc, err := pinProtocolEncrypt(session.version, session.sharedSecret, pinHash[:16])
	if err != nil {
		return nil, err
	}

	command := ctap2.NewClientPINCommand(protocolVersion, ctap2.ClientPINGetPINToken)
	command.KeyAgreement = session.keyAgreement
	command.PINHashEnc = pinHashEnc

	encoded, err := command.Encode()
	if err != nil {
		return nil, err
	}
	responseBytes, err := manager.invoker.InvokeCTAP2(ctx, ctap2.CommandClientPIN, encoded[1:])
	if err != nil {
		return nil, err
	}
	var response ctap2.ClientPINResponse
	if err := command.DecodeResponse(responseBytes, &response); err != nil {
		return nil, err
	}
	if len(response.PinUVAuthToken) == 0 {
		return nil, fmt.Errorf("client: authenticator did not return pinUvAuthToken")
	}
	return pinProtocolDecrypt(session.version, session.sharedSecret, response.PinUVAuthToken)
}

func (manager Manager) getPINProtocolSession(ctx context.Context, protocolVersion uint64) (*pinProtocolSession, error) {
	command := ctap2.NewClientPINCommand(protocolVersion, ctap2.ClientPINGetKeyAgreement)
	encoded, err := command.Encode()
	if err != nil {
		return nil, err
	}
	responseBytes, err := manager.invoker.InvokeCTAP2(ctx, ctap2.CommandClientPIN, encoded[1:])
	if err != nil {
		return nil, err
	}
	var response ctap2.ClientPINResponse
	if err := command.DecodeResponse(responseBytes, &response); err != nil {
		return nil, err
	}
	if response.KeyAgreement == nil {
		return nil, fmt.Errorf("client: authenticator did not return key agreement")
	}
	return newPINProtocolSession(protocolVersion, response.KeyAgreement)
}

func (manager Manager) invokeCredentialManagement(ctx context.Context, command *ctap2.CredentialManagementCommand) (*ctap2.CredentialManagementResponse, error) {
	encoded, err := command.Encode()
	if err != nil {
		return nil, err
	}
	responseBytes, err := manager.invoker.InvokeCTAP2(ctx, command.CommandByte(), encoded[1:])
	if err != nil {
		return nil, err
	}
	var response ctap2.CredentialManagementResponse
	if err := command.DecodeResponse(responseBytes, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

func credentialManagementCommandCode(info *ctap2.GetInfoResponse) (byte, error) {
	if info == nil {
		return 0, fmt.Errorf("client: no capable protocol")
	}
	if optionEnabled(info, "credMgmt") {
		return ctap2.CommandCredentialManagement, nil
	}
	if optionEnabled(info, "credentialMgmtPreview") {
		return ctap2.CommandCredentialManagementPreview, nil
	}
	return 0, fmt.Errorf("client: credential management is not supported")
}

func discoverableCredentialFromResponse(relyingParty relyingPartyCredentialSet, response *ctap2.CredentialManagementResponse) (DiscoverableCredential, error) {
	if response == nil || response.User == nil || response.CredentialID == nil {
		return DiscoverableCredential{}, fmt.Errorf("client: credential management response is incomplete")
	}
	return DiscoverableCredential{
		RP:           relyingParty.RP,
		RPIDHash:     append([]byte(nil), relyingParty.RPIDHash...),
		User:         *response.User,
		Credential:   *response.CredentialID,
		CredProtect:  response.CredProtect,
		LargeBlobKey: append([]byte(nil), response.LargeBlobKey...),
	}, nil
}

func shouldRetryCredentialManagementWithPreview(info *ctap2.GetInfoResponse, err error) bool {
	if info == nil || !optionEnabled(info, "credentialMgmtPreview") {
		return false
	}
	var statusErr *ctap2.Error
	if !errors.As(err, &statusErr) {
		return false
	}
	switch statusErr.Code {
	case 0x01, 0x02, 0x12, 0x14, 0x2b, 0x2c, 0x36, 0x3e, 0x40:
		return true
	default:
		return false
	}
}

func shouldRetryCredentialManagement(err error) bool {
	var statusErr *ctap2.Error
	if !errors.As(err, &statusErr) {
		return false
	}
	return statusErr.Code == 0x12
}

func shouldRetryClientPINChange(err error) bool {
	var statusErr *ctap2.Error
	if !errors.As(err, &statusErr) {
		return false
	}
	return statusErr.Code == 0x12
}

func (manager Manager) changePINOnce(ctx context.Context, info *ctap2.GetInfoResponse, currentPIN []byte, newPIN []byte) error {
	if !optionEnabled(info, "clientPin") {
		return fmt.Errorf("client: authenticator does not have a PIN configured")
	}
	protocolVersion, err := SelectPINUVAuthProtocol(info.PinUVAuthProtocols)
	if err != nil {
		return err
	}
	session, err := manager.getPINProtocolSession(ctx, protocolVersion)
	if err != nil {
		return err
	}

	currentPINHash := sha256.Sum256(currentPIN)
	pinHashEnc, err := pinProtocolEncrypt(session.version, session.sharedSecret, currentPINHash[:16])
	if err != nil {
		return err
	}
	paddedNewPIN, err := padClientPIN(newPIN)
	if err != nil {
		return err
	}
	defer wipeBytes(paddedNewPIN)
	newPINEnc, err := pinProtocolEncrypt(session.version, session.sharedSecret, paddedNewPIN)
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
	command.PinUVAuthParam = PinProtocolAuthenticate(session.version, session.sharedSecret, authMessage)

	encoded, err := command.Encode()
	if err != nil {
		return err
	}
	responseBytes, err := manager.invoker.InvokeCTAP2(ctx, ctap2.CommandClientPIN, encoded[1:])
	if err != nil {
		return err
	}
	var response ctap2.ClientPINResponse
	return command.DecodeResponse(responseBytes, &response)
}

func padClientPIN(pin []byte) ([]byte, error) {
	if len(pin) == 0 {
		return nil, fmt.Errorf("client: new pin is required")
	}
	if len(pin) > clientPINPaddedLength-1 {
		return nil, fmt.Errorf("client: pin length %d exceeds %d bytes", len(pin), clientPINPaddedLength-1)
	}
	padded := make([]byte, clientPINPaddedLength)
	copy(padded, pin)
	return padded, nil
}

func optionPresent(info *ctap2.GetInfoResponse, key string) bool {
	if info == nil || info.Options == nil {
		return false
	}
	_, ok := info.Options[key]
	return ok
}

func optionEnabled(info *ctap2.GetInfoResponse, key string) bool {
	if info == nil || info.Options == nil {
		return false
	}
	return info.Options[key]
}

func wipeBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
