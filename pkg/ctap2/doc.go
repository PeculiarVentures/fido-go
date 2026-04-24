// Package ctap2 implements CTAP2 commands and CBOR-based response handling
// without depending on transport-specific bindings.
//
// The package covers the core low-level command DTOs used by the public SDK:
// authenticatorGetInfo, authenticatorMakeCredential, authenticatorGetAssertion,
// authenticatorClientPIN, authenticatorCredentialManagement, and
// authenticatorReset.
//
// Version support follows the local CTAP mirrors in docs/raw/fido/ctap:
// CTAP2.0 baseline fields are decoded for GetInfo, and CTAP2.1 through CTAP2.3
// response members up to vendorPrototypeConfigCommands are preserved in typed
// fields plus GetInfoResponse.Raw for forward-compatible inspection.
package ctap2
