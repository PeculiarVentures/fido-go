---
name: "Architecture Overview and Integration Rules"
description: "High-level architecture, layer integration, facade API design, and cross-layer coordination rules."
applyTo: "pkg/client/**/*.go,pkg/middleware/**/*.go,**/facade/**/*.go"
---

# Architecture Instructions — FIDO Go Module

## Overview

FIDO Go is a **layered, transport-agnostic FIDO/CTAP implementation** with strict separation of concerns.

```
┌─────────────────────────────────────────┐
│        CLI / Tools                      │
│   (Public user interface)               │
└──────────────┬──────────────────────────┘
               │
┌──────────────┴──────────────────────────┐
│        Client / Facade API              │
│   (Public Go API)                       │
└──────────────┬──────────────────────────┘
               │
    ┌──────────┼──────────┐
    │          │          │
┌───┴──┐  ┌────┴────┐ ┌──┴────┐
│CTAP1 │  │ CTAP2   │ │Middleware
│(U2F) │  │(CBOR)   │ │(Tracing)
└───┬──┘  └────┬────┘ └──┬────┘
    │          │          │
┌───┴──────────┴──────────┴───┐
│    Wire/Framing Layer       │
│  (Packetization & Reassembly)
└───┬──────────┬──────────────┐
    │          │              │
┌───┴──┐  ┌────┴────┐  ┌──────┴────┐
│ USB  │  │ NFC     │  │ BLE       │
│ HID  │  │ (APDU)  │  │ (MTU)     │
└───┬──┘  └────┬────┘  └──────┬────┘
    │          │              │
└────┬─────────┴──────────────┘
     │
┌────┴────────────────────────┐
│  Device / OS / Hardware     │
└─────────────────────────────┘
```

## Core Principles (Non-Negotiable)

### 1. Strict Layering

Each layer has a **single responsibility** and **clear boundary**.

| Layer     | Responsibility                          | MUST NOT                    |
| --------- | --------------------------------------- | --------------------------- |
| Transport | Device discovery, raw exchange, framing | Parse CTAP, know protocols  |
| Wire      | Fragmentation, reassembly               | Understand protocols        |
| CTAP1     | U2F commands, APDU encoding             | Know about other transports |
| CTAP2     | CBOR commands, multi-transport logic    | Know about U2F specifics    |
| Client    | Public API, capability detection, flow  | Violate protocol specs      |
| CLI       | User interface, input/output            | Use internal APIs           |

**Violation = Architectural error.**

### 2. Protocol Isolation

CTAP1 and CTAP2 are **completely separate**.

- Separate packages: `pkg/ctap1`, `pkg/ctap2`
- Separate error types
- Separate command models
- Separate encoders/decoders
- **NO** unified abstractions

### 3. Transport Abstraction

Transport is **pluggable and protocol-agnostic**.

All transports (USB, NFC, BLE) expose:

```go
type Session interface {
    Device() DeviceDescriptor
    Exchange(ctx context.Context, req []byte) ([]byte, error)
    Close() error
}
```

CTAP code **never** knows which transport is active.

### 4. Raw Access

System always supports raw command invocation:

```go
InvokeRaw(ctx, protocol, command, payload) → response
```

This is required for:

- Debugging
- CLI experimentation
- Vendor extensions
- Protocol analysis

### 5. Extensibility via Composition

Cross-cutting concerns use **middleware pattern**:

- Tracing
- Logging
- Retry logic
- Vendor quirks
- Caching

Never embed these directly in protocol logic.

### 6. Capability-Based Behavior

**Detect capabilities at runtime.**

Never assume device capabilities. Always:

1. Call GetInfo (CTAP2) or Version (CTAP1)
2. Check device capabilities
3. Adjust behavior
4. Support fallback (CTAP2 → CTAP1)

## Package Structure

```
fido-go/
├── pkg/
│   ├── client/              # Public API facade
│   │   ├── client.go        # Main client type
│   │   ├── authenticate.go  # Authenticate flow
│   │   ├── register.go      # Register flow
│   │   └── capabilities.go  # Device detection
│   │
│   ├── ctap1/               # U2F protocol (SEPARATE)
│   │   ├── commands.go
│   │   ├── register.go
│   │   ├── authenticate.go
│   │   ├── errors.go
│   │   └── encode.go
│   │
│   ├── ctap2/               # CTAP2 protocol (SEPARATE)
│   │   ├── commands.go
│   │   ├── make_credential.go
│   │   ├── get_assertion.go
│   │   ├── get_info.go
│   │   ├── errors.go
│   │   └── cbor.go
│   │
│   ├── transport/           # Transport abstraction
│   │   ├── session.go       # Session interface
│   │   ├── descriptor.go    # Device descriptor
│   │   ├── usb/             # USB HID transport
│   │   ├── nfc/             # NFC transport
│   │   └── ble/             # BLE transport
│   │
│   ├── wire/                # Framing layer
│   │   ├── codec.go         # Interface
│   │   ├── usb_hid.go       # USB framing
│   │   ├── nfc_apdu.go      # NFC framing
│   │   └── ble_frag.go      # BLE framing
│   │
│   ├── middleware/          # Cross-cutting concerns
│   │   ├── tracing.go       # Request/response tracing
│   │   ├── logging.go       # Structured logging
│   │   └── retry.go         # Automatic retry
│   │
│   └── tracing/             # Trace encoding/display
│       └── traces.go
│
├── cmd/                     # CLI tools
│   ├── fido-go/
│   │   ├── main.go
│   │   ├── commands/
│   │   │   ├── authenticate.go
│   │   │   ├── register.go
│   │   │   ├── list.go
│   │   │   └── raw.go
│   │   └── output/
│   │       ├── json.go
│   │       └── human.go
│   │
├── internal/                # Internal utilities
│   └── cbor/               # CBOR helper (private)
│
└── examples/               # Example code
```

## Client/Facade API Design

### Public API

```go
package client

// Client is the main public interface
type Client interface {
    // Register: Create new credential
    Register(ctx context.Context, attestation AttestationConveyance, opts ...RegisterOption) (*RegistrationResult, error)

    // Authenticate: Verify credential
    Authenticate(ctx context.Context, challenge []byte, opts ...AuthenticateOption) (*AssertionResult, error)

    // GetCapabilities: Detect device capabilities
    GetCapabilities(ctx context.Context) (*DeviceCapabilities, error)

    // InvokeRaw: Send raw protocol command
    InvokeRaw(ctx context.Context, protocol ProtocolFamily, cmdCode int, params []byte) ([]byte, error)

    // Close: Clean up resources
    Close() error
}

// NewClient creates a client for the specified device
func NewClient(ctx context.Context, device *DeviceDescriptor, opts ...ClientOption) (Client, error)
```

### Implementation Pattern

```go
type clientImpl struct {
    session    transport.Session
    middleware []Middleware
    capabilities *DeviceCapabilities
}

func (c *clientImpl) Authenticate(ctx context.Context, challenge []byte, opts ...AuthenticateOption) (*AssertionResult, error) {
    // 1. Detect capabilities (if not cached)
    caps, err := c.detectCapabilities(ctx)
    if err != nil {
        return nil, err
    }

    // 2. Choose protocol: CTAP2 (preferred) → CTAP1 (fallback)
    if caps.CTAP2Available() {
        return c.authenticateCTAP2(ctx, challenge, opts...)
    }
    if caps.CTAP1Available() {
        return c.authenticateCTAP1(ctx, challenge, opts...)
    }

    return nil, ErrNoCapableProtocol
}

func (c *clientImpl) authenticateCTAP2(ctx context.Context, challenge []byte, opts ...AuthenticateOption) (*AssertionResult, error) {
    // Build CTAP2 GetAssertion command
    cmd := ctap2.NewGetAssertionCommand(...)

    // Apply middleware (tracing, logging, etc.)
    payload, err := c.applyMiddleware(cmd.Encode())

    // Send via transport session
    response, err := c.session.Exchange(ctx, payload)

    // Apply middleware to response
    response = c.applyMiddlewareResponse(response)

    // Decode response
    var result ctap2.AssertionResponse
    if err := cmd.DecodeResponse(response, &result); err != nil {
        return nil, err
    }

    return &AssertionResult{...}, nil
}
```

## Error Handling Pattern

Errors are **layered and specific**:

```go
// Transport errors (layer 1)
type TransportError struct {
    Op  string  // "open", "exchange", "close"
    Err error
}

// Wire errors (layer 2)
type FramingError struct {
    Type   string  // "fragmentation", "reassembly"
    Reason string
}

// CTAP1 errors (layer 3)
type CTAP1Error struct {
    StatusWord uint16  // SW1|SW2
    Message    string
}

// CTAP2 errors (layer 3)
type CTAP2Error struct {
    Code    uint8
    Message string
}

// Client errors (layer 4)
type ClientError struct {
    Op     string  // "register", "authenticate"
    Reason string
}
```

## Middleware Pattern

For cross-cutting concerns:

```go
type Middleware interface {
    WrapExchange(next ExchangeFunc) ExchangeFunc
}

type ExchangeFunc func(ctx context.Context, req []byte) ([]byte, error)

// Example: Tracing middleware
type TracingMiddleware struct {
    tracer *Tracer
}

func (t *TracingMiddleware) WrapExchange(next ExchangeFunc) ExchangeFunc {
    return func(ctx context.Context, req []byte) ([]byte, error) {
        t.tracer.LogSent(req)
        resp, err := next(ctx, req)
        t.tracer.LogReceived(resp, err)
        return resp, err
    }
}
```

Register middleware in client:

```go
client := client.New(
    device,
    client.WithMiddleware(tracingMiddleware),
    client.WithMiddleware(loggingMiddleware),
    client.WithMiddleware(retryMiddleware),
)
```

## Device Discovery

Device discovery is **transport-specific** but exposed as unified interface:

```go
package transport

type DeviceDescriptor struct {
    TransportType  string  // "usb", "nfc", "ble"
    Path           string  // Implementation-specific path
    ProductID      uint16
    VendorID       uint16
    SerialNumber   string
    // ... more fields
}

// ListDevices returns all available devices
func ListDevices(ctx context.Context) ([]*DeviceDescriptor, error) {
    devices := []*DeviceDescriptor{}

    // USB discovery
    usbDevices, _ := usb.ListDevices(ctx)
    devices = append(devices, usbDevices...)

    // NFC discovery
    nfcDevices, _ := nfc.ListDevices(ctx)
    devices = append(devices, nfcDevices...)

    // BLE discovery
    bleDevices, _ := ble.ListDevices(ctx)
    devices = append(devices, bleDevices...)

    return devices, nil
}
```

## Capability Detection

Clients MUST detect capabilities before choosing protocol:

```go
func (c *clientImpl) detectCapabilities(ctx context.Context) (*Capabilities, error) {
    // Try CTAP2 GetInfo
    cmd := ctap2.NewGetInfoCommand()
    payload, _ := cmd.Encode()

    if response, err := c.session.Exchange(ctx, payload); err == nil {
        var caps ctap2.AuthenticatorCapabilities
        if cmd.DecodeResponse(response, &caps) == nil {
            return &Capabilities{
                CTAP2: &caps,
                ProtocolVersion: "2.1", // or detected version
            }, nil
        }
    }

    // Fallback: Try CTAP1 Version
    cmd := ctap1.NewVersionCommand()
    if response, err := c.session.Exchange(ctx, cmd.Encode()); err == nil {
        var version string
        if cmd.DecodeResponse(response, &version) == nil && version == "U2F_V2" {
            return &Capabilities{
                CTAP1: true,
                ProtocolVersion: "1.0",
            }, nil
        }
    }

    return nil, ErrNoCapableProtocol
}
```

## Integration Checklist

When adding a new feature or layer:

- [ ] Identify which layer owns the feature
- [ ] Ensure it doesn't violate layer boundaries
- [ ] Add appropriate error types
- [ ] Create tests at layer level (with mocks)
- [ ] Update layer-specific instructions if needed
- [ ] Document public APIs only
- [ ] Consider middleware for cross-cutting concerns
- [ ] Update architecture documentation

## Summary

**Architecture = Strict Layers, Clear Boundaries, Extensible**

- Transport ↔ Wire ↔ CTAP1/CTAP2 ↔ Client ↔ CLI
- CTAP1 and CTAP2 completely separate
- All transports uniform interface
- Middleware for cross-cutting concerns
- Capability-based behavior
- Raw access always available
- Errors specific and layered
- Public API only in client layer
