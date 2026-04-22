---
name: "Wire Layer Rules"
description: "Rules for implementing and modifying framing, packetization, and packet reassembly logic for different transports."
applyTo: "wire/**/*.go,**/wire/**/*.go,**/framing/**/*.go"
---

# Wire Layer Instructions — FIDO Go Module

## Scope

Wire layer code handles:

- packet-level framing (packetization of payloads)
- fragmentation and reassembly
- packet validation and integrity checks
- transport-specific packet structure handling

## Hard Boundaries

Wire code MUST:

- remain completely protocol-agnostic
- handle fragmentation/reassembly transparently
- encapsulate packet-level details from upper layers
- expose a simple byte-oriented interface

Wire code MUST NOT:

- parse CTAP commands or responses
- understand CBOR or protocol semantics
- validate CTAP-level data (only framing integrity)
- implement protocol versioning logic
- contain transport I/O logic (belongs in transport layer)

## Key Principle: Framing is Transport-Specific

Each transport has different framing:

- **USB HID**: Report IDs, fixed packet sizes, continuation packets
- **NFC/APDU**: APDU wrapping, chaining, status words
- **BLE**: Fragment reassembly, MTU handling, characteristic boundaries

Wire implementations MUST:

- isolate these details per transport
- NOT create a "universal framing" that leaks complexity
- keep framing fully encapsulated within Session.Exchange()

Upper layers MUST:

- call `Exchange(ctx, completePayload)` and receive `completeResponse`
- never see incomplete packets or framing boundaries

## Fragmentation Pattern

When a payload exceeds transport limits:

```go
// Good: Session handles fragmentation internally
response, err := session.Exchange(ctx, largePayload)

// BAD: Caller must manage framing - WRONG
response1, err := session.SendPacket(ctx, packet1)
response2, err := session.SendPacket(ctx, packet2)  // ❌ NEVER
```

## Reassembly Rules

For multi-packet responses:

- Collect all fragments
- Validate reassembly integrity (checksums, sequence numbers where applicable)
- Return complete payload to caller
- Never expose partial/incomplete data

## Error Handling

Wire layer errors MUST be structured:

- Framing errors (invalid packet structure)
- Reassembly errors (incomplete or corrupted fragments)
- Timeout or cancellation from context

DO NOT wrap these in generic errors. Be specific about what failed and where.

## Transport-Specific Implementations

### USB HID Wire

- Handle HID report IDs
- Implement continuation packet logic (CTAP over HID)
- Enforce max packet size constraints
- Validate report structure

### NFC Wire

- Wrap APDU commands
- Handle C-APDU/R-APDU structure
- Manage chaining (CLA byte chain bit)
- Treat status words as framing-level, not semantic

### BLE Wire

- Handle MTU negotiation results
- Implement fragment reassembly (UUIDs, sequences)
- Manage characteristic write/read limits
- No assumption about packet boundaries

## No Protocol Knowledge Required

Wire code should be testable with:

- arbitrary byte sequences
- synthetic fragmentation scenarios
- mock transport sessions

Wire tests MUST NOT:

- use real CTAP commands
- validate protocol semantics
- know about CTAP1 or CTAP2

Wire tests SHOULD:

- test fragmentation edge cases
- test incomplete/corrupted packet scenarios
- test timeout and cancellation

## Design Pattern

```go
// Wire interface (internal to transport)
type wireCodec interface {
    // Fragment payload into packets
    Fragment(payload []byte) ([][]byte, error)
    // Reassemble packets into payload
    Reassemble(packets [][]byte) ([]byte, error)
    // Validate packet structure
    ValidatePacket(packet []byte) error
}

// Session exposes only raw Exchange
type Session interface {
    Exchange(ctx context.Context, req []byte) ([]byte, error)
    // (Fragmentation/reassembly handled internally)
}
```

## Testing Wire Code

Create separate test packages for each wire implementation:

```
wire/
  usb_hid/
    packet_test.go       // Packet structure tests
    fragmentation_test.go
    reassembly_test.go
  nfc/
    apdu_test.go
  ble/
    fragment_test.go
```

Test with synthetic data, not real device communication.

## Summary

**Wire layer = Transport Framing ONLY**

- In: raw complete payload
- Process: packetize, handle fragmentation rules
- Out: raw complete response
- Constraint: Protocol-agnostic throughout
