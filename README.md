# fido-go

`fido-go` is a Go SDK for working with FIDO authenticators with strict separation between transport, framing, CTAP protocol logic, and public client APIs.

The repository is in active bootstrap. Stage 1 establishes the SDK foundation used by later CTAP1/CTAP2, transport, and CLI work:

- `pkg/protocol` defines protocol-family primitives shared by the public API.
- `pkg/transport` defines the transport-agnostic session contract and device descriptor.
- `pkg/middleware` defines the exchange middleware pipeline for tracing, logging, retries, and vendor quirks.
- `pkg/client` defines the public client facade for raw protocol dispatch through pluggable protocol invokers.

The current code intentionally stops at architectural boundaries. Typed CTAP1/CTAP2 commands, transport implementations, and CLI flows will land in later stages.

## Architecture direction

The SDK is being built around a strict layered model:

- transport sessions expose raw byte exchange only
- middleware composes tracing, logging, retries, and quirks handling
- protocol-specific packages own CTAP1 and CTAP2 command models separately
- the public client facade remains the only API surface that higher-level tools should consume

## Build and test

```sh
go test ./...
```
