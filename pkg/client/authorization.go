package client

// DefaultUVAuthorization returns the default user-verification authorization.
// Credential-management operations keep their existing behavior and prompt for
// a PIN when no explicit authorization input is supplied.
func DefaultUVAuthorization() UVAuthorization {
	return UVAuthorization{}
}

// PINAuthorization returns an explicit ClientPIN authorization from a string.
// The PIN is copied into the returned UVAuthorization. Callers that keep the
// authorization for reuse may wipe authorization.PIN after the final use.
func PINAuthorization(pin string) UVAuthorization {
	return UVAuthorization{Method: VerificationMethodPIN, PIN: NewSecretString(pin)}
}

// SecretPINAuthorization returns an explicit ClientPIN authorization using a
// caller-owned secret. The SDK does not wipe the supplied secret.
func SecretPINAuthorization(pin Secret) UVAuthorization {
	return UVAuthorization{Method: VerificationMethodPIN, PIN: pin}
}

// BuiltInUVAuthorization requests authenticator-side built-in user verification.
func BuiltInUVAuthorization() UVAuthorization {
	return UVAuthorization{Method: VerificationMethodBuiltInUV}
}
