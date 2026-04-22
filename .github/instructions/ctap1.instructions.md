---
name: "CTAP1 (U2F) Protocol Rules"
description: "Rules for implementing CTAP1 (U2F) protocol logic, command types, encoding/decoding, and error handling."
applyTo: "pkg/ctap1/**/*.go,**/ctap1/**/*.go"
---

# CTAP1 Instructions — FIDO Go Module

## Scope

CTAP1 (U2F) implementation covers:

- U2F command types (Register, Authenticate, Version)
- Command encoding and response decoding
- APDU wrapping (ISO7816-4 structure)
- CTAP1-specific error handling
- Capability detection

## Separation from CTAP2

CTAP1 and CTAP2 are **completely independent** protocols.

MUST:

- implement in separate `ctap1` and `ctap2` packages
- use separate command types
- use separate error codes
- use separate encoders/decoders

MUST NOT:

- share command interfaces between CTAP1 and CTAP2
- create unified "Command" abstraction
- use inheritance or type embedding to share logic
- route commands through shared pipelines

## Protocol Boundary

CTAP1 can ONLY:

- run over USB (HID)
- run over NFC (APDU wrapping)

CTAP1 cannot:

- assume BLE support
- require CBOR (CTAP2 is CBOR-based)
- use CTAP2 extensions

## Command Model

All CTAP1 commands MUST implement:

```go
type Command interface {
    Protocol() ProtocolFamily  // returns CTAP1
    Encode() ([]byte, error)
    DecodeResponse([]byte, responseData interface{}) error
}
```

### U2F Commands

**Register** (0x01):

- Input: challenge, appID, [optional: key handles]
- Output: attestation certificate, signature, public key
- Error: returns CTAP1 status codes

**Authenticate** (0x02):

- Input: control byte, challenge, appID, [optional: key handles]
- Output: signature counter, signature
- Error: handling per control byte

**Version** (0x03):

- Input: none (implicit)
- Output: version string (typically "U2F_V2")

## Encoding Rules

CTAP1 commands are encoded as APDU (ISO7816-4):

```
APDU Structure:
CLA | INS | P1  | P2  | [LC | DATA | LE]
```

For U2F:

- **CLA**: 0x00
- **INS**: command ID (0x01, 0x02, 0x03)
- **P1, P2**: control bytes (protocol-specific)
- **LC**: length of data
- **DATA**: command payload
- **LE**: expected response length

MUST encode correctly per U2F spec. DO NOT:

- skip APDU structure
- modify APDU fields arbitrarily
- assume device parsing is forgiving

## Response Handling

CTAP1 responses follow APDU format:

```
Response: [DATA] | SW1 | SW2
```

Status word (SW1|SW2) meanings:

- **0x6985**: Conditions not satisfied
- **0x6a80**: Invalid request data
- **0x6a82**: File not found
- **0x9000**: Success

MUST:

- parse status words correctly
- return appropriate Go errors
- preserve original status codes in error types

Responses may include user presence checks and conditions.

## Error Handling

CTAP1 errors MUST be typed and distinct:

```go
// CTAP1-specific error type
type CTAP1Error struct {
    StatusWord uint16  // SW1|SW2
    Message    string
}
```

DO NOT:

- return generic errors
- lose status word information
- conflate CTAP1 errors with CTAP2 errors

## Capability Detection

Device capabilities for CTAP1 MUST:

- be detected at runtime via Version command
- support fallback behavior in client layer (not CTAP1 layer)
- not assume device supports all U2F features

## Session Expectations

CTAP1 assumes transport session provides:

```go
type Session interface {
    Exchange(ctx context.Context, apdu []byte) ([]byte, error)
}
```

MUST NOT:

- assume specific transport type
- require USB HID directly
- access transport internals

## Testing CTAP1

Create test packages:

```
ctap1/
  commands/
    register_test.go
    authenticate_test.go
    version_test.go
  encoding/
    apdu_test.go
    encode_test.go
    decode_test.go
  errors_test.go
```

Tests SHOULD:

- verify APDU encoding per spec
- test status word parsing
- test command/response round-trips
- NOT require real devices

Use synthetic session mocks:

```go
type MockSession struct {
    ResponseData []byte
}

func (m *MockSession) Exchange(ctx context.Context, apdu []byte) ([]byte, error) {
    // Return synthetic responses
}
```

## Documentation References

Refer to:

- FIDO U2F Specification (main spec)
- FIDO CTAP Specification (for CTAP1 details)
- ISO 7816-4 (APDU structure)

Link to these in code comments where applicable.

## Vendor Quirks

CTAP1 device quirks MUST:

- be handled by middleware (not in protocol layer)
- be registered in extension system
- NOT modify core CTAP1 logic

Example: "Device X returns non-standard status words"

→ Register vendor workaround as middleware, not in CTAP1 code

## Summary

**CTAP1 = Stateless U2F Protocol**

- Separate from CTAP2 entirely
- Encode/decode APDU structure correctly
- Return CTAP1-specific errors
- Assume generic transport session
- Extensible for vendor quirks via middleware
