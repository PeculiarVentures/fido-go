---
name: "CTAP2 Protocol Rules"
description: "Rules for implementing CTAP2 protocol logic, command types, CBOR encoding/decoding, and error handling."
applyTo: "pkg/ctap2/**/*.go,**/ctap2/**/*.go"
---

# CTAP2 Instructions — FIDO Go Module

## Scope

CTAP2 implementation covers:

- HID, NFC, and BLE transport support
- CBOR-based command/response encoding
- Authenticator commands (GetInfo, MakeCredential, GetAssertion, etc.)
- CTAP2-specific error handling and status codes
- Capability and extension handling
- PIN and user verification
- Authenticator configuration

## Separation from CTAP1

CTAP2 and CTAP1 are **completely independent** protocols.

MUST:

- implement in separate `ctap2` package (distinct from `ctap1`)
- use separate command types
- use separate error codes and status codes
- use separate encoders/decoders
- support all CTAP2 transports independently

MUST NOT:

- share command interfaces between CTAP1 and CTAP2
- create unified "Command" abstraction
- use inheritance or type embedding
- route commands through shared pipelines

## Transport Support

CTAP2 runs over:

- **USB HID**: CBOR over HID packets
- **NFC**: CBOR over APDU wrapping
- **BLE**: CBOR over BLE characteristics

Each transport MUST be independent.

DO NOT:

- assume all devices support all transports
- create "universal CTAP2" that requires specific transport
- mandate transport features in protocol code

## Command Model

All CTAP2 commands MUST implement:

```go
type Command interface {
    Protocol() ProtocolFamily  // returns CTAP2
    Encode() ([]byte, error)   // CBOR encoding
    DecodeResponse([]byte, responseData interface{}) error
}
```

### CTAP2 Commands

**GetInfo** (0x04):

- Input: none
- Output: authenticator capabilities, extensions, options
- Usage: Protocol discovery and capability detection

**MakeCredential** (0x01):

- Input: client data hash, user info, credential parameters, options
- Output: credential, public key, attestation
- Usage: Registration

**GetAssertion** (0x02):

- Input: RP ID, client data hash, allow credentials, options
- Output: credential ID, user info, signature, auth data
- Usage: Authentication

**ClientPin** (0x06):

- Input: subcommand, protocol version, pin/uv
- Output: pin token
- Usage: Authentication and PIN management

**Reset** (0x07):

- Input: none
- Output: success or error
- Usage: Factory reset

**GetNextAssertion** (0x08):

- Input: none
- Output: next assertion response
- Usage: Multiple credentials

**BioEnrollment** (0x09):

- Input: subcommand, biometric data
- Output: enrollment results
- Usage: Biometric registration

**Credential Management** (0x0A):

- Input: subcommand, credential info
- Output: credential metadata
- Usage: Credential operations

For each command, implement:

- Correct CBOR key mappings
- Mandatory vs. optional parameters
- Proper error conditions per spec

## CBOR Encoding Rules

CTAP2 uses CBOR (RFC 8949) with specific conventions:

MUST:

- use canonical CBOR encoding where spec requires
- respect key order and parameter positions
- support variable-length maps and arrays
- validate parameter types strictly

MUST NOT:

- assume loose CBOR parsing
- skip parameter validation
- use non-standard encodings

### Encoding Pattern

```go
// Encode: Command → CBOR bytes
type EncodeFunc func(cmd Command) ([]byte, error)

// Decode: CBOR bytes → Response
type DecodeFunc func(data []byte, resp interface{}) error
```

Test with:

- Valid CBOR sequences from spec examples
- Edge cases (empty arrays, nested maps, null values)
- Invalid CBOR (malformed, wrong types)

## Error Handling

CTAP2 defines status codes (0x00 - 0xFF):

```
0x00 = CTAP1_ERR_SUCCESS
0x01 = CTAP1_ERR_INVALID_COMMAND
0x02 = CTAP1_ERR_INVALID_PARAMETER
0x03 = CTAP1_ERR_INVALID_LENGTH
...
0x10 = CTAP2_ERR_CBOR_PARSING
0x11 = CTAP2_ERR_CBOR_UNEXPECTED_TYPE
...
```

MUST:

- return CTAP2-specific error types
- preserve status codes in errors
- distinguish CBOR errors from semantic errors
- never conflate CTAP1 and CTAP2 errors

```go
type CTAP2Error struct {
    Code    uint8  // CTAP2 status code
    Message string
}
```

## Response Handling

CTAP2 response format:

```
Response: [0x00 | CBOR_DATA] or [STATUS_CODE]
```

- **0x00**: Success (followed by optional CBOR data)
- **Non-zero**: Error code

Responses MUST:

- parse status code first
- handle empty responses (success with no data)
- decode CBOR only on success
- preserve exact response structure

## Capability Detection

Authenticators report capabilities via GetInfo:

```go
type AuthenticatorCapabilities struct {
    Versions      []string  // ["FIDO_2_0", ...]
    Extensions    []string  // ["hmac-secret", ...]
    Transports    []string  // ["usb", "nfc", "ble", ...]
    MaxMsgSize    int
    PinUvAuthProtocol int
    // ... more fields
}
```

MUST:

- detect capabilities at runtime
- support fallback behavior in client layer
- NOT assume device capabilities
- respect device-reported feature limits

## Options and Flags

CTAP2 supports authenticator options:

- rk (resident key support)
- uv (user verification support)
- clientPin (PIN support)
- credentialMgmtPreview
- bioEnrollment
- userVerification
- residentKey
- others per spec

MUST:

- respect option flags per device
- handle unsupported options gracefully
- provide clear error messages for incompatible options

## Extension Handling

CTAP2 supports extensions (vendor-specific features).

Extension logic MUST:

- be isolated from core CTAP2
- use registration/middleware patterns
- NOT modify protocol logic
- support custom extension handlers

Standard extensions:

- hmac-secret
- credProtect
- minPinLength
- others per spec

## Session Expectations

CTAP2 assumes transport session provides:

```go
type Session interface {
    Exchange(ctx context.Context, payload []byte) ([]byte, error)
}
```

Payload structure:

- First byte: CTAP2 command code
- Remaining bytes: CBOR-encoded parameters

Response structure:

- First byte: status code
- Remaining bytes: CBOR data (if success)

MUST NOT:

- assume specific transport
- require USB HID
- access transport internals

## Testing CTAP2

Create test packages:

```
ctap2/
  commands/
    get_info_test.go
    make_credential_test.go
    get_assertion_test.go
    client_pin_test.go
    reset_test.go
  encoding/
    cbor_test.go
    encode_test.go
    decode_test.go
  errors_test.go
  options_test.go
  extensions_test.go
```

Tests SHOULD:

- verify CBOR encoding per spec
- test status code parsing
- test command/response round-trips
- test capability detection
- test error conditions

Use synthetic session mocks with test vectors from CTAP2 spec.

## Vendor Extensions

Vendor-specific behavior MUST:

- be isolated from core CTAP2
- be registered via extension registry
- NOT modify base protocol logic
- be well-documented

Example:

```go
// Vendor quirk: Device X returns non-standard response format
type VendorXExtension struct {}

func (v *VendorXExtension) DecodeResponse(data []byte) (interface{}, error) {
    // Handle vendor-specific decoding
}

// Register in client layer, not CTAP2 layer
```

## Documentation References

Refer to:

- FIDO2 Specification (main spec)
- CTAP2 Specification (normative)
- RFC 8949 (CBOR)
- WebAuthn Specification (usage context)

Link to these in code comments where applicable.

## Summary

**CTAP2 = Multi-Transport, CBOR-Based Protocol**

- Completely separate from CTAP1
- CBOR encoding/decoding per spec
- Support all CTAP2 transports independently
- Return CTAP2-specific errors and status codes
- Detect capabilities at runtime
- Extensible for vendor quirks via middleware
- Support all standard commands and extensions
