---
name: "Architecture Overview and Integration Rules"
description: "High-level architecture, layer integration, facade API design, and cross-layer coordination rules."
applyTo: "pkg/client/**/*.go,pkg/middleware/**/*.go,**/facade/**/*.go"
---

# Architecture Instructions — FIDO Go Module

## Overview

FIDO Go is a layered, transport-agnostic FIDO/CTAP SDK and CLI.

```text
cmd/fidoctl
  ↓
internal/cli/fidoctl
  ↓
pkg/client facade
  ↓
pkg/ctap1 + pkg/ctap2 command models
  ↓
pkg/transport sessions
  ↓
pkg/wire/{hid,nfc,ble} framing
```

## Core Rules

- Transport packages discover devices, open sessions, and exchange complete raw byte payloads.
- Wire packages fragment and reassemble packets only; they do not know CTAP semantics.
- CTAP1 and CTAP2 stay separate. Do not introduce a unified CTAP command abstraction across both protocols.
- `pkg/client` is the public facade. It owns capability probing, protocol selection, high-level registration/authentication, CTAP2 management orchestration, secret handling, and trace policy.
- CLI code must use public `pkg/client` APIs through `internal/cli/fidoctl`; it must not bypass the facade for authenticator access.
- Raw access through `Client.InvokeRaw(ctx, family, command, payload)` must remain available for diagnostics and vendor extensions.

## Current Package Structure

```text
cmd/fidoctl/                  # Cobra command wiring, parsing, output
internal/cli/fidoctl/         # CLI service layer over pkg/client
pkg/client/                   # Public SDK facade
pkg/ctap1/                    # CTAP1/U2F APDU commands and status errors
pkg/ctap2/                    # CTAP2 CBOR command DTOs and status errors
pkg/middleware/               # Exchange middleware chain
pkg/protocol/                 # Protocol-family identifiers
pkg/transport/                # Device/session/backend abstractions
pkg/transport/{usb,nfc,ble}/  # Transport backend implementations/foundations
pkg/wire/{hid,nfc,ble}/       # Framing codecs
scripts/                      # Development tools
docs/raw/fido/                # Local FIDO specs
```

## Public Client API

Current client API uses request structs, explicit raw invokers, defensive capability copies, and `client.Secret` for PIN-like values.

```go
type Client interface {
    Device() transport.DeviceDescriptor
    Capabilities(ctx context.Context) (*Capabilities, error)
    CTAP2(ctx context.Context) (CTAP2Client, error)
    Register(ctx context.Context, request RegistrationRequest) (*RegistrationResult, error)
    Authenticate(ctx context.Context, request AuthenticationRequest) (*AuthenticationResult, error)
    InvokeRaw(ctx context.Context, family protocol.Family, command byte, payload []byte) ([]byte, error)
    Close() error
}

type PINManager interface {
    Status(ctx context.Context) (*PINStatus, error)
    Set(ctx context.Context, newPIN Secret) error
    Change(ctx context.Context, currentPIN Secret, newPIN Secret) error
}
```

Do not reintroduce compatibility aliases such as `DeviceCapabilities`, `RegisterRequest`, `AuthenticateRequest`, or `AssertionResult`; the project is not published and stale aliases should be removed.

## Capability Handling

- `Client.Capabilities(ctx)` probes CTAP2 GetInfo and CTAP1 Version, caches the canonical result internally, and returns a defensive copy.
- Callers must not rely on mutating returned capabilities.
- Add a refresh API only if a feature genuinely needs re-probing after authenticator state changes.

## Secret Handling

- PIN and authorization material must use `client.Secret`, not `string`.
- Secret values should be wiped by callers after use when possible.
- SDK code must wipe temporary padded PINs, tokens, shared secrets, hashes, and decrypted buffers where practical.
- Do not add JSON tags that serialize PIN values.

## Trace Policy

- Trace is redacted by default for CTAP2 ClientPIN and credential-management commands.
- Full raw trace is allowed only through explicit unsafe opt-in, e.g. `TraceOptions{RedactSecrets:false}` or CLI `--unsafe-include-secrets`.
- New diagnostics must preserve this safe default.

## PIN/UV Auth Protocol

- `pkg/client` currently implements PIN/UV auth protocol 1 and 2 for CTAP2 ClientPIN flows.
- Protocol selection should prefer version 2 when the authenticator reports it, with fallback to version 1.
- Behavior must be grounded in local CTAP specs under `docs/raw/fido/ctap`.

## Middleware

Middleware wraps raw exchanges only:

```go
type ExchangeFunc func(ctx context.Context, req []byte) ([]byte, error)

type Middleware interface {
    WrapExchange(next ExchangeFunc) ExchangeFunc
}
```

Use middleware for cross-cutting behavior such as tracing, retry, logging, and vendor quirks. Do not put protocol semantics in middleware unless the middleware is explicitly a protocol-aware client-layer feature.

## Integration Checklist

- Identify the owning layer before changing code.
- Keep CTAP1, CTAP2, transport, wire, client, and CLI boundaries intact.
- Prefer stable facade DTOs for high-level API; use `pkg/ctap2` DTOs only for explicit low-level/advanced surfaces.
- Add tests at the narrowest layer that owns the behavior.
- Use local FIDO specs for protocol-sensitive changes.
- Update `.github` instructions, README/docs, and review files when architecture or public API changes.
