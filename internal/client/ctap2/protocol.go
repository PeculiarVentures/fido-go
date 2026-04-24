package clientctap2

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"github.com/PeculiarVentures/fido-go/pkg/ctap2"
)

// Invoker executes raw CTAP2 commands for the internal management layer.
type Invoker interface {
	InvokeCTAP2(ctx context.Context, command byte, payload []byte) ([]byte, error)
}

// InvokerFunc adapts a function to the Invoker interface.
type InvokerFunc func(ctx context.Context, command byte, payload []byte) ([]byte, error)

// InvokeCTAP2 executes one raw CTAP2 command.
func (fn InvokerFunc) InvokeCTAP2(ctx context.Context, command byte, payload []byte) ([]byte, error) {
	return fn(ctx, command, payload)
}

type pinProtocolSession struct {
	version      uint64
	sharedSecret []byte
	keyAgreement map[int64]any
}

// SelectPINUVAuthProtocol prefers pinUvAuthProtocol 2 with fallback to 1.
func SelectPINUVAuthProtocol(protocols []uint64) (uint64, error) {
	if len(protocols) == 0 {
		return 1, nil
	}
	for _, protocolVersion := range protocols {
		if protocolVersion == 2 {
			return 2, nil
		}
	}
	for _, protocolVersion := range protocols {
		if protocolVersion == 1 {
			return 1, nil
		}
	}
	return 0, fmt.Errorf("client: supported pinUvAuthProtocol not found")
}

// COSEEC2PublicKey decodes a COSE EC2 public key into an ECDH public key.
func COSEEC2PublicKey(coseKey map[int64]any) (*ecdh.PublicKey, error) {
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

// PinProtocolAuthParam computes a credential-management pinUvAuthParam.
func PinProtocolAuthParam(protocolVersion uint64, key []byte, command *ctap2.CredentialManagementCommand) ([]byte, error) {
	message, err := command.AuthenticationMessage()
	if err != nil {
		return nil, err
	}
	return PinProtocolAuthenticate(protocolVersion, key, message), nil
}

// PinProtocol1AuthParam computes a protocol 1 credential-management pinUvAuthParam.
func PinProtocol1AuthParam(key []byte, command *ctap2.CredentialManagementCommand) ([]byte, error) {
	return PinProtocolAuthParam(1, key, command)
}

func pinProtocolKDF(protocolVersion uint64, sharedPoint []byte) ([]byte, error) {
	switch protocolVersion {
	case 1:
		sharedSecret := sha256.Sum256(sharedPoint)
		return append([]byte(nil), sharedSecret[:]...), nil
	case 2:
		salt := make([]byte, 32)
		hmacKey, err := hkdf.Key(sha256.New, sharedPoint, salt, "CTAP2 HMAC key", 32)
		if err != nil {
			return nil, fmt.Errorf("client: derive pinUvAuthProtocol 2 HMAC key: %w", err)
		}
		aesKey, err := hkdf.Key(sha256.New, sharedPoint, salt, "CTAP2 AES key", 32)
		if err != nil {
			return nil, fmt.Errorf("client: derive pinUvAuthProtocol 2 AES key: %w", err)
		}
		return append(hmacKey, aesKey...), nil
	default:
		return nil, fmt.Errorf("client: unsupported pinUvAuthProtocol %d", protocolVersion)
	}
}

func pinProtocolEncrypt(protocolVersion uint64, key []byte, plaintext []byte) ([]byte, error) {
	switch protocolVersion {
	case 1:
		return PinProtocol1Encrypt(key, plaintext)
	case 2:
		return pinProtocol2Encrypt(key, plaintext)
	default:
		return nil, fmt.Errorf("client: unsupported pinUvAuthProtocol %d", protocolVersion)
	}
}

func pinProtocolDecrypt(protocolVersion uint64, key []byte, ciphertext []byte) ([]byte, error) {
	switch protocolVersion {
	case 1:
		return PinProtocol1Decrypt(key, ciphertext)
	case 2:
		return pinProtocol2Decrypt(key, ciphertext)
	default:
		return nil, fmt.Errorf("client: unsupported pinUvAuthProtocol %d", protocolVersion)
	}
}

// PinProtocolAuthenticate computes a pinUvAuthParam for the requested protocol.
func PinProtocolAuthenticate(protocolVersion uint64, key []byte, message []byte) []byte {
	if protocolVersion == 2 {
		return pinProtocol2Authenticate(key, message)
	}
	return PinProtocol1Authenticate(key, message)
}

// PinProtocol1Encrypt encrypts data with pinUvAuthProtocol 1 semantics.
func PinProtocol1Encrypt(key []byte, plaintext []byte) ([]byte, error) {
	if len(plaintext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("client: plaintext length %d is not a multiple of %d", len(plaintext), aes.BlockSize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("client: create AES cipher: %w", err)
	}
	iv := make([]byte, aes.BlockSize)
	ciphertext := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, plaintext)
	return ciphertext, nil
}

// PinProtocol1Decrypt decrypts data with pinUvAuthProtocol 1 semantics.
func PinProtocol1Decrypt(key []byte, ciphertext []byte) ([]byte, error) {
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("client: ciphertext length %d is not a multiple of %d", len(ciphertext), aes.BlockSize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("client: create AES cipher: %w", err)
	}
	iv := make([]byte, aes.BlockSize)
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ciphertext)
	return plaintext, nil
}

func pinProtocol2Encrypt(key []byte, plaintext []byte) ([]byte, error) {
	if len(key) < 64 {
		return nil, fmt.Errorf("client: pinUvAuthProtocol 2 shared secret is too short")
	}
	if len(plaintext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("client: plaintext length %d is not a multiple of %d", len(plaintext), aes.BlockSize)
	}
	block, err := aes.NewCipher(key[32:64])
	if err != nil {
		return nil, fmt.Errorf("client: create AES cipher: %w", err)
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("client: generate pinUvAuthProtocol 2 IV: %w", err)
	}
	ciphertext := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, plaintext)
	return append(iv, ciphertext...), nil
}

func pinProtocol2Decrypt(key []byte, ciphertext []byte) ([]byte, error) {
	if len(key) < 64 {
		return nil, fmt.Errorf("client: pinUvAuthProtocol 2 shared secret is too short")
	}
	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("client: pinUvAuthProtocol 2 ciphertext is too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ct := ciphertext[aes.BlockSize:]
	if len(ct)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("client: ciphertext length %d is not a multiple of %d", len(ct), aes.BlockSize)
	}
	block, err := aes.NewCipher(key[32:64])
	if err != nil {
		return nil, fmt.Errorf("client: create AES cipher: %w", err)
	}
	plaintext := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ct)
	return plaintext, nil
}

// PinProtocol1Authenticate computes a protocol 1 pinUvAuthParam.
func PinProtocol1Authenticate(key []byte, message []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(message)
	signature := mac.Sum(nil)
	return append([]byte(nil), signature[:16]...)
}

func pinProtocol2Authenticate(key []byte, message []byte) []byte {
	if len(key) > 32 {
		key = key[:32]
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(message)
	return mac.Sum(nil)
}

func newPINProtocolSession(protocolVersion uint64, peerKeyAgreement map[int64]any) (*pinProtocolSession, error) {
	curve := ecdh.P256()
	peerPublicKey, err := COSEEC2PublicKey(peerKeyAgreement)
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
	sharedSecret, err := pinProtocolKDF(protocolVersion, sharedPoint)
	if err != nil {
		return nil, err
	}
	publicKeyBytes := privateKey.PublicKey().Bytes()
	return &pinProtocolSession{
		version:      protocolVersion,
		sharedSecret: sharedSecret,
		keyAgreement: map[int64]any{
			1:  int64(2),
			3:  int64(-25),
			-1: int64(1),
			-2: append([]byte(nil), publicKeyBytes[1:33]...),
			-3: append([]byte(nil), publicKeyBytes[33:65]...),
		},
	}, nil
}
