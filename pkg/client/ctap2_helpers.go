package client

import (
	"context"
	"crypto/ecdh"

	clientctap2 "github.com/PeculiarVentures/fido-go/internal/client/ctap2"
	"github.com/PeculiarVentures/fido-go/pkg/ctap2"
	"github.com/PeculiarVentures/fido-go/pkg/protocol"
)

func (client *client) ctap2Manager() clientctap2.Manager {
	return clientctap2.New(clientctap2.InvokerFunc(func(ctx context.Context, command byte, payload []byte) ([]byte, error) {
		return client.InvokeRaw(ctx, protocol.FamilyCTAP2, command, payload)
	}))
}

func selectPINUVAuthProtocol(protocols []uint64) (uint64, error) {
	return clientctap2.SelectPINUVAuthProtocol(protocols)
}

func normalizeCredentialDescriptor(credential CredentialDescriptor) (ctap2.CredentialDescriptor, error) {
	return clientctap2.NormalizeCredentialDescriptor(credentialDescriptorToCTAP2(credential))
}

func coseEC2PublicKey(coseKey map[int64]any) (*ecdh.PublicKey, error) {
	return clientctap2.COSEEC2PublicKey(coseKey)
}

func pinProtocolAuthParam(protocolVersion uint64, key []byte, command *ctap2.CredentialManagementCommand) ([]byte, error) {
	return clientctap2.PinProtocolAuthParam(protocolVersion, key, command)
}

func pinProtocol1AuthParam(key []byte, command *ctap2.CredentialManagementCommand) ([]byte, error) {
	return clientctap2.PinProtocol1AuthParam(key, command)
}

func pinProtocolAuthenticate(protocolVersion uint64, key []byte, message []byte) []byte {
	return clientctap2.PinProtocolAuthenticate(protocolVersion, key, message)
}

func pinProtocol1Encrypt(key []byte, plaintext []byte) ([]byte, error) {
	return clientctap2.PinProtocol1Encrypt(key, plaintext)
}

func pinProtocol1Decrypt(key []byte, ciphertext []byte) ([]byte, error) {
	return clientctap2.PinProtocol1Decrypt(key, ciphertext)
}

func pinProtocol1Authenticate(key []byte, message []byte) []byte {
	return clientctap2.PinProtocol1Authenticate(key, message)
}
