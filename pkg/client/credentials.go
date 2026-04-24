package client

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/PeculiarVentures/fido-go/pkg/ctap2"
	"github.com/PeculiarVentures/fido-go/pkg/protocol"
)

// DiscoverableCredential describes one resident credential returned by credential management.
type DiscoverableCredential struct {
	RP           ctap2.RelyingPartyEntity   `json:"rp"`
	RPIDHash     []byte                     `json:"rpIdHash,omitempty"`
	User         ctap2.UserEntity           `json:"user"`
	Credential   ctap2.CredentialDescriptor `json:"credential"`
	CredProtect  uint64                     `json:"credProtect,omitempty"`
	LargeBlobKey []byte                     `json:"largeBlobKey,omitempty"`
}

// CredentialListResult contains credential-management metadata and the enumerated credentials.
type CredentialListResult struct {
	ExistingResidentCredentialsCount             uint64                   `json:"existingResidentCredentialsCount,omitempty"`
	MaxPossibleRemainingResidentCredentialsCount uint64                   `json:"maxPossibleRemainingResidentCredentialsCount,omitempty"`
	Credentials                                  []DiscoverableCredential `json:"credentials"`
}

type relyingPartyCredentialSet struct {
	RP       ctap2.RelyingPartyEntity
	RPIDHash []byte
}

type pinProtocol1Session struct {
	sharedSecret []byte
	keyAgreement map[int64]any
}

// ListCredentials enumerates discoverable credentials using CTAP2 credential management.
func (client *client) ListCredentials(ctx context.Context, pin string) (*CredentialListResult, error) {
	if pin == "" {
		return nil, ErrPINRequired
	}

	caps, err := client.requireCTAP2Capabilities(ctx, "listing discoverable credentials")
	if err != nil {
		return nil, err
	}

	commandCode, err := credentialManagementCommandCode(caps)
	if err != nil {
		return nil, err
	}
	protocolVersion, err := selectPINUVAuthProtocol(caps.PinUVAuthProtocols)
	if err != nil {
		return nil, err
	}
	result, err := client.listCredentialsWithCommand(ctx, commandCode, protocolVersion, pin)
	if err == nil {
		return result, nil
	}
	if shouldRetryCredentialManagement(err) {
		retried, retryErr := client.listCredentialsWithCommand(ctx, commandCode, protocolVersion, pin)
		if retryErr == nil {
			return retried, nil
		}
		err = retryErr
	}
	if commandCode == ctap2.CommandCredentialManagement && shouldRetryCredentialManagementWithPreview(caps, err) {
		return client.listCredentialsWithCommand(ctx, ctap2.CommandCredentialManagementPreview, protocolVersion, pin)
	}
	return nil, err
}

// DeleteCredential removes one discoverable credential using CTAP2 credential management.
func (client *client) DeleteCredential(ctx context.Context, credential ctap2.CredentialDescriptor, pin string) error {
	if pin == "" {
		return ErrPINRequired
	}

	normalized, err := normalizeCredentialDescriptor(credential)
	if err != nil {
		return err
	}

	caps, err := client.requireCTAP2Capabilities(ctx, "deleting discoverable credentials")
	if err != nil {
		return err
	}

	commandCode, err := credentialManagementCommandCode(caps)
	if err != nil {
		return err
	}
	protocolVersion, err := selectPINUVAuthProtocol(caps.PinUVAuthProtocols)
	if err != nil {
		return err
	}
	err = client.deleteCredentialWithCommand(ctx, commandCode, protocolVersion, normalized, pin)
	if err == nil {
		return nil
	}
	if shouldRetryCredentialManagement(err) {
		retryErr := client.deleteCredentialWithCommand(ctx, commandCode, protocolVersion, normalized, pin)
		if retryErr == nil {
			return nil
		}
		err = retryErr
	}
	if commandCode == ctap2.CommandCredentialManagement && shouldRetryCredentialManagementWithPreview(caps, err) {
		return client.deleteCredentialWithCommand(ctx, ctap2.CommandCredentialManagementPreview, protocolVersion, normalized, pin)
	}
	return err
}

func (client *client) listCredentialsWithCommand(ctx context.Context, commandCode byte, protocolVersion uint64, pin string) (*CredentialListResult, error) {
	pinToken, err := client.getCredentialManagementPINToken(ctx, commandCode, protocolVersion, pin)
	if err != nil {
		return nil, err
	}

	result, err := client.getCredentialMetadata(ctx, commandCode, protocolVersion, pinToken)
	if err != nil {
		return nil, err
	}
	if result.ExistingResidentCredentialsCount == 0 {
		return result, nil
	}

	relyingParties, err := client.enumerateRelyingParties(ctx, commandCode, protocolVersion, pinToken)
	if err != nil {
		return nil, err
	}
	for _, relyingParty := range relyingParties {
		credentials, err := client.enumerateCredentials(ctx, commandCode, protocolVersion, pinToken, relyingParty)
		if err != nil {
			return nil, err
		}
		result.Credentials = append(result.Credentials, credentials...)
	}
	return result, nil
}

func (client *client) getCredentialManagementPINToken(ctx context.Context, commandCode byte, protocolVersion uint64, pin string) ([]byte, error) {
	if commandCode == ctap2.CommandCredentialManagementPreview {
		return client.getPINToken(ctx, protocolVersion, pin)
	}
	return client.getPINTokenWithPermissions(ctx, protocolVersion, pin, ctap2.PermissionCredentialManagement, "")
}

func (client *client) getCredentialMetadata(ctx context.Context, commandCode byte, protocolVersion uint64, pinToken []byte) (*CredentialListResult, error) {
	command := ctap2.NewCredentialManagementCommand(commandCode, ctap2.CredentialManagementGetMetadata)
	command.PinUVAuthProtocol = protocolVersion
	pinUVAuthParam, err := pinProtocol1AuthParam(pinToken, command)
	if err != nil {
		return nil, err
	}
	command.PinUVAuthParam = pinUVAuthParam

	response, err := client.invokeCredentialManagement(ctx, command)
	if err != nil {
		return nil, err
	}
	return &CredentialListResult{
		ExistingResidentCredentialsCount:             response.ExistingResidentCredentialsCount,
		MaxPossibleRemainingResidentCredentialsCount: response.MaxPossibleRemainingResidentCredentialsCount,
	}, nil
}

func (client *client) enumerateRelyingParties(ctx context.Context, commandCode byte, protocolVersion uint64, pinToken []byte) ([]relyingPartyCredentialSet, error) {
	command := ctap2.NewCredentialManagementCommand(commandCode, ctap2.CredentialManagementEnumerateRPsBegin)
	command.PinUVAuthProtocol = protocolVersion
	pinUVAuthParam, err := pinProtocol1AuthParam(pinToken, command)
	if err != nil {
		return nil, err
	}
	command.PinUVAuthParam = pinUVAuthParam

	response, err := client.invokeCredentialManagement(ctx, command)
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
		nextResponse, err := client.invokeCredentialManagement(ctx, nextCommand)
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

func (client *client) enumerateCredentials(ctx context.Context, commandCode byte, protocolVersion uint64, pinToken []byte, relyingParty relyingPartyCredentialSet) ([]DiscoverableCredential, error) {
	command := ctap2.NewCredentialManagementCommand(commandCode, ctap2.CredentialManagementEnumerateCredentialsBegin)
	command.SubcommandParams = &ctap2.CredentialManagementSubcommandParams{RPIDHash: append([]byte(nil), relyingParty.RPIDHash...)}
	command.PinUVAuthProtocol = protocolVersion
	pinUVAuthParam, err := pinProtocol1AuthParam(pinToken, command)
	if err != nil {
		return nil, err
	}
	command.PinUVAuthParam = pinUVAuthParam

	response, err := client.invokeCredentialManagement(ctx, command)
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
		nextResponse, err := client.invokeCredentialManagement(ctx, nextCommand)
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

func (client *client) deleteCredentialWithCommand(ctx context.Context, commandCode byte, protocolVersion uint64, credential ctap2.CredentialDescriptor, pin string) error {
	pinToken, err := client.getCredentialManagementPINToken(ctx, commandCode, protocolVersion, pin)
	if err != nil {
		return err
	}

	command := ctap2.NewCredentialManagementCommand(commandCode, ctap2.CredentialManagementDeleteCredential)
	command.SubcommandParams = &ctap2.CredentialManagementSubcommandParams{CredentialID: &credential}
	command.PinUVAuthProtocol = protocolVersion
	pinUVAuthParam, err := pinProtocol1AuthParam(pinToken, command)
	if err != nil {
		return err
	}
	command.PinUVAuthParam = pinUVAuthParam

	_, err = client.invokeCredentialManagement(ctx, command)
	return err
}

func (client *client) getPINTokenWithPermissions(ctx context.Context, protocolVersion uint64, pin string, permissions ctap2.Permission, permissionsRPID string) ([]byte, error) {
	session, err := client.getPINProtocol1Session(ctx, protocolVersion)
	if err != nil {
		return nil, err
	}
	pinHash := sha256.Sum256([]byte(pin))
	pinHashEnc, err := pinProtocol1Encrypt(session.sharedSecret, pinHash[:16])
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
	responseBytes, err := client.InvokeRaw(ctx, protocol.FamilyCTAP2, ctap2.CommandClientPIN, encoded[1:])
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
	return pinProtocol1Decrypt(session.sharedSecret, response.PinUVAuthToken)
}

func (client *client) getPINToken(ctx context.Context, protocolVersion uint64, pin string) ([]byte, error) {
	session, err := client.getPINProtocol1Session(ctx, protocolVersion)
	if err != nil {
		return nil, err
	}
	pinHash := sha256.Sum256([]byte(pin))
	pinHashEnc, err := pinProtocol1Encrypt(session.sharedSecret, pinHash[:16])
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
	responseBytes, err := client.InvokeRaw(ctx, protocol.FamilyCTAP2, ctap2.CommandClientPIN, encoded[1:])
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
	return pinProtocol1Decrypt(session.sharedSecret, response.PinUVAuthToken)
}

func (client *client) getPINProtocol1Session(ctx context.Context, protocolVersion uint64) (*pinProtocol1Session, error) {
	command := ctap2.NewClientPINCommand(protocolVersion, ctap2.ClientPINGetKeyAgreement)
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
	if len(response.KeyAgreement) == 0 {
		return nil, fmt.Errorf("client: authenticator did not return key agreement")
	}
	return newPINProtocol1Session(response.KeyAgreement)
}

func (client *client) invokeCredentialManagement(ctx context.Context, command *ctap2.CredentialManagementCommand) (*ctap2.CredentialManagementResponse, error) {
	encoded, err := command.Encode()
	if err != nil {
		return nil, err
	}
	responseBytes, err := client.InvokeRaw(ctx, protocol.FamilyCTAP2, command.CommandByte(), encoded[1:])
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
		return 0, ErrNoCapableProtocol
	}
	if info.Options["credMgmt"] {
		return ctap2.CommandCredentialManagement, nil
	}
	if info.Options["credentialMgmtPreview"] {
		return ctap2.CommandCredentialManagementPreview, nil
	}
	return 0, fmt.Errorf("client: credential management is not supported")
}

func selectPINUVAuthProtocol(protocols []uint64) (uint64, error) {
	if len(protocols) == 0 {
		return 1, nil
	}
	for _, protocolVersion := range protocols {
		if protocolVersion == 1 {
			return 1, nil
		}
	}
	return 0, fmt.Errorf("client: pinUvAuthProtocol 1 is not supported by this authenticator")
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

func normalizeCredentialDescriptor(credential ctap2.CredentialDescriptor) (ctap2.CredentialDescriptor, error) {
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

func shouldRetryCredentialManagementWithPreview(info *ctap2.GetInfoResponse, err error) bool {
	if info == nil || !info.Options["credentialMgmtPreview"] {
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

func newPINProtocol1Session(peerKeyAgreement map[int64]any) (*pinProtocol1Session, error) {
	curve := ecdh.P256()
	peerPublicKey, err := coseEC2PublicKey(peerKeyAgreement)
	if err != nil {
		return nil, err
	}
	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("client: generate key agreement key: %w", err)
	}
	sharedPoint, err := privateKey.ECDH(peerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("client: derive shared secret: %w", err)
	}
	sharedSecret := sha256.Sum256(sharedPoint)
	publicKeyBytes := privateKey.PublicKey().Bytes()
	return &pinProtocol1Session{
		sharedSecret: append([]byte(nil), sharedSecret[:]...),
		keyAgreement: map[int64]any{
			1:  int64(2),
			3:  int64(-25),
			-1: int64(1),
			-2: append([]byte(nil), publicKeyBytes[1:33]...),
			-3: append([]byte(nil), publicKeyBytes[33:65]...),
		},
	}, nil
}

func coseEC2PublicKey(coseKey map[int64]any) (*ecdh.PublicKey, error) {
	xCoordinate, err := coseEC2Coordinate(coseKey, -2)
	if err != nil {
		return nil, err
	}
	yCoordinate, err := coseEC2Coordinate(coseKey, -3)
	if err != nil {
		return nil, err
	}
	encoded := make([]byte, 65)
	encoded[0] = 0x04
	copy(encoded[1:33], xCoordinate)
	copy(encoded[33:65], yCoordinate)
	publicKey, err := ecdh.P256().NewPublicKey(encoded)
	if err != nil {
		return nil, fmt.Errorf("client: parse COSE EC2 public key: %w", err)
	}
	return publicKey, nil
}

func coseEC2Coordinate(coseKey map[int64]any, key int64) ([]byte, error) {
	value, ok := coseKey[key]
	if !ok {
		return nil, fmt.Errorf("client: COSE key is missing coordinate %d", key)
	}
	coordinate, ok := value.([]byte)
	if !ok {
		return nil, fmt.Errorf("client: COSE key coordinate %d has unexpected type %T", key, value)
	}
	if len(coordinate) > 32 {
		return nil, fmt.Errorf("client: COSE key coordinate %d is too long", key)
	}
	if len(coordinate) == 32 {
		return append([]byte(nil), coordinate...), nil
	}
	padded := make([]byte, 32)
	copy(padded[32-len(coordinate):], coordinate)
	return padded, nil
}

func pinProtocol1AuthParam(key []byte, command *ctap2.CredentialManagementCommand) ([]byte, error) {
	message, err := command.AuthenticationMessage()
	if err != nil {
		return nil, err
	}
	return pinProtocol1Authenticate(key, message), nil
}

func pinProtocol1Encrypt(key []byte, plaintext []byte) ([]byte, error) {
	if len(plaintext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("client: plaintext length %d is not a multiple of %d", len(plaintext), aes.BlockSize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("client: create AES cipher: %w", err)
	}
	iv := make([]byte, aes.BlockSize)
	ciphertext := make([]byte, len(plaintext))
	encrypter := cipher.NewCBCEncrypter(block, iv)
	encrypter.CryptBlocks(ciphertext, plaintext)
	return ciphertext, nil
}

func pinProtocol1Decrypt(key []byte, ciphertext []byte) ([]byte, error) {
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("client: ciphertext length %d is not a multiple of %d", len(ciphertext), aes.BlockSize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("client: create AES cipher: %w", err)
	}
	iv := make([]byte, aes.BlockSize)
	plaintext := make([]byte, len(ciphertext))
	decrypter := cipher.NewCBCDecrypter(block, iv)
	decrypter.CryptBlocks(plaintext, ciphertext)
	return plaintext, nil
}

func pinProtocol1Authenticate(key []byte, message []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(message)
	signature := mac.Sum(nil)
	return append([]byte(nil), signature[:16]...)
}
