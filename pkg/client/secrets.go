package client

// Secret holds sensitive caller-provided bytes such as authenticator PINs.
//
// Prefer constructing Secret values from byte slices so interactive flows can
// avoid transient string copies in memory. Secret values are mutable so callers
// can wipe them after use. The SDK copies secrets at API boundaries when it
// needs to retain a value beyond validation.
type Secret []byte

// NewSecret copies bytes into a wipeable secret value.
func NewSecret(value []byte) Secret {
	if len(value) == 0 {
		return nil
	}
	return Secret(append([]byte(nil), value...))
}

// NewSecretString copies a string into a wipeable secret value.
func NewSecretString(value string) Secret {
	if value == "" {
		return nil
	}
	return NewSecret([]byte(value))
}

// Empty reports whether the secret has no bytes.
func (secret Secret) Empty() bool {
	return len(secret) == 0
}

// Clone returns a copy of the secret bytes.
func (secret Secret) Clone() Secret {
	return NewSecret(secret)
}

// Wipe overwrites the bytes currently held by this Secret value.
func (secret Secret) Wipe() {
	for index := range secret {
		secret[index] = 0
	}
}

func wipeBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
