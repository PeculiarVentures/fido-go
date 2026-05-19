package client

import (
	"context"
	"fmt"

	"github.com/PeculiarVentures/fido-go/pkg/ctap2"
)

// AuthenticatorInfo aliases the raw authenticatorGetInfo response for CTAP2 callers.
type AuthenticatorInfo = ctap2.GetInfoResponse

// CTAP2Client exposes CTAP2-specific management and administration operations.
type CTAP2Client interface {
	Info(ctx context.Context) (*AuthenticatorInfo, error)
	PIN() PINManager
	Credentials() CredentialManager
	Bio() BioManager
	Reset(ctx context.Context) error
}

// PINManager exposes CTAP2 ClientPIN operations.
type PINManager interface {
	Status(ctx context.Context) (*PINStatus, error)
	Set(ctx context.Context, newPIN Secret) error
	Change(ctx context.Context, currentPIN Secret, newPIN Secret) error
}

// PINStatus summarizes the current PIN configuration state.
type PINStatus struct {
	Configured       bool   `json:"configured"`
	Retries          uint64 `json:"retries,omitempty"`
	UVRetries        uint64 `json:"uvRetries,omitempty"`
	PowerCycleNeeded bool   `json:"powerCycleNeeded,omitempty"`
}

// UVAuthorization describes one explicit authorization input for CTAP2 management.
type UVAuthorization struct {
	PIN    Secret             `json:"-"`
	Method VerificationMethod `json:"method,omitempty"`
}

// CredentialManager exposes CTAP2 credential-management operations.
type CredentialManager interface {
	List(ctx context.Context, authorization UVAuthorization) (*CredentialListResult, error)
	Delete(ctx context.Context, credential CredentialDescriptor, authorization UVAuthorization) error
}

// BioEnrollment describes one provisioned biometric enrollment.
type BioEnrollment struct {
	FriendlyName string `json:"friendlyName,omitempty"`
}

// BioManager exposes CTAP2 bio-enrollment capabilities.
type BioManager interface {
	Supported(ctx context.Context) (bool, error)
	Enrollments(ctx context.Context, authorization UVAuthorization) ([]BioEnrollment, error)
}

type ctap2Surface struct {
	client *client
}

type pinManager struct {
	client *client
}

type credentialManager struct {
	client *client
}

type bioManager struct {
	client *client
}

type credentialAuthorization struct {
	Method VerificationMethod
	PIN    Secret
	Info   *ctap2.GetInfoResponse
}

const credentialManagementOperation = "credential management"

// CTAP2 returns the CTAP2-specific management surface for the selected authenticator.
func (client *client) CTAP2(ctx context.Context) (CTAP2Client, error) {
	caps, err := client.Capabilities(ctx)
	if err != nil {
		return nil, err
	}
	if !caps.HasCTAP2() {
		return nil, &CTAP2UnavailableError{Device: client.Device()}
	}
	return ctap2Surface{client: client}, nil
}

func (surface ctap2Surface) Info(ctx context.Context) (*AuthenticatorInfo, error) {
	caps, err := surface.client.Capabilities(ctx)
	if err != nil {
		return nil, err
	}
	if caps.RawCTAP2 == nil {
		return nil, &CTAP2UnavailableError{Device: surface.client.Device()}
	}
	return cloneGetInfoResponse(caps.RawCTAP2), nil
}

func (surface ctap2Surface) PIN() PINManager {
	return pinManager(surface)
}

func (surface ctap2Surface) Credentials() CredentialManager {
	return credentialManager(surface)
}

func (surface ctap2Surface) Bio() BioManager {
	return bioManager(surface)
}

func (surface ctap2Surface) Reset(ctx context.Context) error {
	return surface.client.Reset(ctx)
}

func (manager pinManager) Status(ctx context.Context) (*PINStatus, error) {
	info, err := manager.client.requireCTAP2Capabilities(ctx, "reading PIN status")
	if err != nil {
		return nil, err
	}
	if !optionPresent(info, "clientPin") {
		return nil, fmt.Errorf("client: authenticator does not support clientPin")
	}
	status := &PINStatus{Configured: optionEnabled(info, "clientPin")}
	if !status.Configured {
		return status, nil
	}
	retries, err := manager.client.GetPINRetries(ctx)
	if err != nil {
		return nil, err
	}
	status.Retries = retries.PINRetries
	status.UVRetries = retries.UVRetries
	status.PowerCycleNeeded = retries.PowerCycleState
	return status, nil
}

func (manager pinManager) Set(ctx context.Context, newPIN Secret) error {
	return manager.client.SetPIN(ctx, newPIN)
}

func (manager pinManager) Change(ctx context.Context, currentPIN Secret, newPIN Secret) error {
	return manager.client.ChangePIN(ctx, currentPIN, newPIN)
}

func (manager credentialManager) List(ctx context.Context, authorization UVAuthorization) (*CredentialListResult, error) {
	resolved, err := manager.resolveCredentialAuthorization(ctx, authorization, "list credentials", "Enter authenticator PIN to list discoverable credentials")
	if err != nil {
		return nil, err
	}
	if resolved.Method == VerificationMethodBuiltInUV {
		return manager.client.listCredentialsWithBuiltInUV(ctx, resolved.Info)
	}
	return manager.client.ListCredentials(ctx, resolved.PIN)
}

func (manager credentialManager) Delete(ctx context.Context, credential CredentialDescriptor, authorization UVAuthorization) error {
	resolved, err := manager.resolveCredentialAuthorization(ctx, authorization, "delete credential", "Enter authenticator PIN to delete a discoverable credential")
	if err != nil {
		return err
	}
	if resolved.Method == VerificationMethodBuiltInUV {
		return manager.client.deleteCredentialWithBuiltInUV(ctx, credential, resolved.Info)
	}
	return manager.client.DeleteCredential(ctx, credential, resolved.PIN)
}

func (manager credentialManager) resolveCredentialAuthorization(ctx context.Context, authorization UVAuthorization, operation string, message string) (credentialAuthorization, error) {
	method := authorization.Method
	if method == "" {
		method = VerificationMethodPIN
	}

	switch method {
	case VerificationMethodPIN:
		return manager.resolveCredentialPINAuthorization(ctx, authorization, operation, message)
	case VerificationMethodBuiltInUV:
		info, err := manager.requireCredentialManagementBuiltInUV(ctx)
		if err != nil {
			return credentialAuthorization{}, err
		}
		return credentialAuthorization{Method: VerificationMethodBuiltInUV, Info: info}, nil
	default:
		return credentialAuthorization{}, &UnsupportedVerificationMethodError{Method: method, Operation: credentialManagementOperation}
	}
}

func (manager credentialManager) resolveCredentialPINAuthorization(ctx context.Context, authorization UVAuthorization, operation string, message string) (credentialAuthorization, error) {
	pin := authorization.PIN
	if pin.Empty() {
		resolvedPIN, err := manager.client.requestPIN(ctx, PINRequest{
			Operation: operation,
			Protocol:  FamilyCTAP2,
			Method:    VerificationMethodPIN,
			Message:   message,
		})
		if err != nil {
			return credentialAuthorization{}, err
		}
		pin = resolvedPIN
	}
	return credentialAuthorization{Method: VerificationMethodPIN, PIN: pin}, nil
}

func (manager credentialManager) requireCredentialManagementBuiltInUV(ctx context.Context) (*ctap2.GetInfoResponse, error) {
	info, err := manager.client.requireCTAP2Capabilities(ctx, credentialManagementOperation)
	if err != nil {
		return nil, err
	}
	if !optionPresent(info, "uv") {
		return nil, &VerificationMethodUnavailableError{Method: VerificationMethodBuiltInUV, Operation: credentialManagementOperation}
	}
	if !optionEnabled(info, "uv") {
		return nil, &VerificationMethodUnavailableError{
			Method:    VerificationMethodBuiltInUV,
			Operation: credentialManagementOperation,
			Reason:    "authenticator built-in UV is not configured",
		}
	}
	if !optionEnabled(info, "pinUvAuthToken") {
		return nil, &VerificationMethodUnavailableError{
			Method:    VerificationMethodBuiltInUV,
			Operation: credentialManagementOperation,
			Reason:    "authenticator does not support pinUvAuthToken for built-in UV",
		}
	}
	if !optionEnabled(info, "credMgmt") {
		if optionEnabled(info, "credentialMgmtPreview") {
			return nil, &UnsupportedVerificationMethodError{Method: VerificationMethodBuiltInUV, Operation: "credential management preview"}
		}
		return nil, fmt.Errorf("client: credential management is not supported")
	}
	return info, nil
}

func (manager bioManager) Supported(ctx context.Context) (bool, error) {
	info, err := manager.client.requireCTAP2Capabilities(ctx, "reading bio enrollment capabilities")
	if err != nil {
		return false, err
	}
	return optionPresent(info, "bioEnroll"), nil
}

func (manager bioManager) Enrollments(ctx context.Context, _ UVAuthorization) ([]BioEnrollment, error) {
	info, err := manager.client.requireCTAP2Capabilities(ctx, "enumerating bio enrollments")
	if err != nil {
		return nil, err
	}
	if !optionPresent(info, "bioEnroll") {
		return nil, fmt.Errorf("client: bio enrollment is not supported")
	}
	if !optionEnabled(info, "bioEnroll") {
		return []BioEnrollment{}, nil
	}
	return nil, fmt.Errorf("client: bio enrollment enumeration is not implemented")
}

func cloneGetInfoResponse(info *ctap2.GetInfoResponse) *ctap2.GetInfoResponse {
	return info.Clone()
}
