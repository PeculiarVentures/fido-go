---
name: "Transport Layer Rules"
description: "Rules for implementing and modifying transport backends, transport sessions, framing, and low-level device communication for USB HID, NFC, and BLE."
applyTo: "transport/**/*.go,**/transport/**/*.go,**/*transport*.go,wire/**/*.go,**/wire/**/*.go"
---

# Transport Instructions — FIDO Go Module

## Scope

These instructions apply to:

- transport backends
- transport sessions
- device discovery code
- framing, fragmentation, and reassembly
- low-level byte exchange with USB HID, NFC, and BLE devices

Apply these rules when creating, modifying, or reviewing transport-related code.

## Role of the transport layer

The transport layer is responsible for:

- device discovery
- opening and closing sessions
- sending and receiving raw byte payloads
- handling transport-specific framing
- handling transport-specific connection details

The transport layer is **not** responsible for CTAP semantics.

## Hard boundaries

Transport code MUST:

- remain protocol-agnostic
- expose a minimal byte-oriented session interface
- encapsulate transport-specific framing internally
- keep device and OS interaction isolated from higher layers

Transport code MUST NOT:

- parse CTAP command semantics
- interpret CBOR payload meaning
- implement CTAP1 or CTAP2 business rules
- decide protocol fallback behavior
- contain CLI logic

If a transport change requires knowledge of CTAP semantics, the design is wrong and must be reconsidered.

## Session model

Transport sessions SHOULD expose a simple abstraction similar to:

```go
type Session interface {
    Device() DeviceDescriptor
    Exchange(ctx context.Context, req []byte) ([]byte, error)
    Close() error
}
```

`Exchange` MUST:

- accept a complete raw payload
- return a complete raw response
- fully handle fragmentation and reassembly internally
- respect context cancellation and deadlines

`Exchange` MUST NOT:

- expose partial packets to higher layers
- require callers to manage framing
- leak transport-specific packet structures upward

## Framing rules

Framing belongs to the transport or wire layer only.

Framing code MUST:

- packetize outbound payloads
- reassemble inbound payloads
- validate framing integrity where practical
- keep packet-level details hidden from CTAP code

Framing code MUST NOT:

- contain command-level protocol logic
- require CTAP code to understand packet boundaries
- mix transport framing with semantic decoding

## Transport-specific expectations

### USB HID

USB HID code MUST:

- implement HID packet framing correctly
- respect report size constraints
- manage channel initialization if required
- handle multi-packet message assembly

### NFC

NFC code MUST:

- implement APDU wrapping and unwrapping as transport mechanics
- respect ISO7816 constraints
- handle chaining where required
- treat APDU transport handling as framing, not CTAP semantics

### BLE

BLE code MUST:

- handle MTU limitations
- fragment and reassemble payloads internally
- manage connection lifecycle explicitly
- handle timeout and latency behavior carefully

## Discovery rules

Discovery code MUST:

- enumerate devices without opening full sessions unless required
- return structured device descriptors
- avoid heavy probing in the discovery step
- keep transport metadata separate from protocol capability detection

Discovery code MUST NOT:

- infer CTAP feature support from transport presence alone
- perform protocol negotiation as part of normal listing

## Error handling

Transport code MUST return transport-layer errors only.

Examples include:

- device unavailable
- permission denied
- connection lost
- timeout
- malformed frame
- I/O failure

Transport code MUST NOT:

- convert CTAP status codes into transport errors
- swallow low-level failures
- return vague generic errors when a specific transport error is available

Prefer typed, layer-aware errors.

## Concurrency

Transport implementations MUST define concurrency behavior clearly.

Preferred default:

- a session is not thread-safe unless explicitly designed and documented otherwise

Transport code MUST NOT:

- allow unsafe concurrent access accidentally
- hide race-prone shared state across sessions
- rely on implicit serialization without clear ownership

## Retries and timeouts

Transport code MUST:

- respect `context.Context`
- fail predictably on timeout
- avoid indefinite blocking

Transport code MAY:

- retry transient low-level I/O issues when safe and bounded

Transport code MUST NOT:

- retry semantic protocol failures
- mask repeated transport failures behind silent recovery

## Tracing integration

Transport code SHOULD integrate with the shared tracing system.

Tracing at this layer SHOULD:

- emit raw payload events
- include transport metadata
- help diagnose framing and I/O issues

Transport code MUST NOT:

- introduce its own separate logging model
- couple tracing to protocol semantics
- change runtime behavior when tracing is enabled

## Adding a new transport

When adding a new transport:

- implement the transport and session abstractions
- keep the implementation isolated
- integrate through registry or manager patterns
- avoid modifying CTAP logic

Adding a new transport MUST NOT require:

- changing CTAP1 code
- changing CTAP2 code
- changing command models
- adding transport conditionals into higher layers

## Testing guidance

Transport code SHOULD be testable with:

- mockable sessions
- framing unit tests
- golden tests for fragmentation and reassembly
- simulated or fake devices where possible

Tests SHOULD verify:

- correct packetization
- correct response reconstruction
- timeout and cancellation handling
- stable error behavior

## Preferred design choices

Prefer:

- explicit session lifecycle
- isolated per-transport implementations
- minimal interfaces
- deterministic error handling
- complete message exchange abstractions

Avoid:

- premature cross-transport abstractions
- shared mutable state across backends
- protocol-aware transport helpers
- hidden behavior

## Stop conditions

Stop and redesign if you are about to:

- parse CTAP command meaning in transport code
- expose packet fragments to upper layers
- make CTAP code aware of HID, APDU, or BLE framing details
- add vendor-specific protocol behavior directly into core transport code
- modify transport code to compensate for protocol design mistakes elsewhere

## Documentation update rule

When transport behavior changes, review whether updates are required in:

- transport README files
- architecture instructions
- transport-specific instructions
- CLI or diagnostics documentation
- tracing documentation

Transport documentation should stay concise and explain:

- what the transport layer owns
- what it does not own
- what guarantees it provides to upper layers
