package client

import (
	"context"

	clientctap2 "github.com/PeculiarVentures/fido-go/internal/client/ctap2"
	"github.com/PeculiarVentures/fido-go/pkg/ctap2"
)

// DiscoverableCredential describes one resident credential returned by credential management.
type DiscoverableCredential struct {
	RP           ctap2.RelyingPartyEntity `json:"rp"`
	RPIDHash     []byte                   `json:"rpIdHash,omitempty"`
	User         ctap2.UserEntity         `json:"user"`
	Credential   CredentialDescriptor     `json:"credential"`
	CredProtect  uint64                   `json:"credProtect,omitempty"`
	LargeBlobKey []byte                   `json:"largeBlobKey,omitempty"`
}

// CredentialListResult contains credential-management metadata and the enumerated credentials.
type CredentialListResult struct {
	ExistingResidentCredentialsCount             uint64                   `json:"existingResidentCredentialsCount,omitempty"`
	MaxPossibleRemainingResidentCredentialsCount uint64                   `json:"maxPossibleRemainingResidentCredentialsCount,omitempty"`
	Credentials                                  []DiscoverableCredential `json:"credentials"`
}

// ListCredentials enumerates discoverable credentials using CTAP2 credential management.
func (client *client) ListCredentials(ctx context.Context, pin Secret) (*CredentialListResult, error) {
	if pin.Empty() {
		return nil, ErrPINRequired
	}

	info, err := client.requireCTAP2Capabilities(ctx, "listing discoverable credentials")
	if err != nil {
		return nil, err
	}
	result, err := client.ctap2Manager().ListCredentials(ctx, info, pin)
	if err != nil {
		return nil, err
	}
	return credentialListResultFromInternal(result), nil
}

func (client *client) listCredentialsWithBuiltInUV(ctx context.Context, info *ctap2.GetInfoResponse) (*CredentialListResult, error) {
	result, err := client.ctap2Manager().ListCredentialsWithBuiltInUV(ctx, info)
	if err != nil {
		return nil, err
	}
	return credentialListResultFromInternal(result), nil
}

// DeleteCredential removes one discoverable credential using CTAP2 credential management.
func (client *client) DeleteCredential(ctx context.Context, credential CredentialDescriptor, pin Secret) error {
	if pin.Empty() {
		return ErrPINRequired
	}

	normalized, err := normalizeCredentialDescriptor(credential)
	if err != nil {
		return err
	}

	info, err := client.requireCTAP2Capabilities(ctx, "deleting discoverable credentials")
	if err != nil {
		return err
	}

	return client.ctap2Manager().DeleteCredential(ctx, info, normalized, pin)
}

func (client *client) deleteCredentialWithBuiltInUV(ctx context.Context, credential CredentialDescriptor, info *ctap2.GetInfoResponse) error {
	normalized, err := normalizeCredentialDescriptor(credential)
	if err != nil {
		return err
	}

	return client.ctap2Manager().DeleteCredentialWithBuiltInUV(ctx, info, normalized)
}

func credentialListResultFromInternal(result *clientctap2.CredentialListResult) *CredentialListResult {
	if result == nil {
		return nil
	}
	converted := &CredentialListResult{
		ExistingResidentCredentialsCount:             result.ExistingResidentCredentialsCount,
		MaxPossibleRemainingResidentCredentialsCount: result.MaxPossibleRemainingResidentCredentialsCount,
	}
	if len(result.Credentials) != 0 {
		converted.Credentials = make([]DiscoverableCredential, len(result.Credentials))
		for index, credential := range result.Credentials {
			converted.Credentials[index] = DiscoverableCredential{
				RP:           credential.RP,
				RPIDHash:     append([]byte(nil), credential.RPIDHash...),
				User:         credential.User,
				Credential:   credentialDescriptorFromCTAP2(credential.Credential),
				CredProtect:  credential.CredProtect,
				LargeBlobKey: append([]byte(nil), credential.LargeBlobKey...),
			}
		}
	}
	return converted
}
