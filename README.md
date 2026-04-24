# fido-go

`fido-go` is a Go SDK for working with FIDO authenticators with strict separation between transport, framing, CTAP protocol logic, and public client APIs.

The repository is in active bootstrap. The current implementation covers the first six stages of the roadmap:

- `pkg/protocol` defines protocol-family primitives shared by the public API.
- `pkg/transport` defines the transport-agnostic session contract and device descriptor.
- `pkg/middleware` defines the exchange middleware pipeline for tracing, logging, retries, and vendor quirks.
- `pkg/client` defines the public client facade for raw protocol dispatch and capability probing.
- `pkg/ctap1` implements the `U2F_VERSION` command and APDU helpers used for CTAP1 capability detection.
- `pkg/ctap1` also implements typed `U2F_REGISTER` and `U2F_AUTHENTICATE` command encoding/decoding.
- `pkg/ctap2` implements the `authenticatorGetInfo (0x04)` command and capability response decoding.
- `pkg/ctap2` also provides typed foundations for `authenticatorMakeCredential`, `authenticatorGetAssertion`, `authenticatorClientPIN`, `authenticatorCredentialManagement`, and `authenticatorReset`.
- `pkg/wire` provides protocol-agnostic framing foundations for USB HID, NFC/APDU, and BLE packetization.
- `pkg/transport` provides a backend registry, injectable transport backends, a real USB HID backend, and a PC/SC-backed NFC backend for local CTAP sessions.
- `pkg/client` now also exposes discovery, tracing, register/authenticate/reset helpers, resident-key registration controls, discoverable-credential enumeration and deletion, and CTAP2 PIN changes for user-facing tooling.
- `cmd/fidoctl` provides a Cobra-based CLI for device discovery, capability inspection, tracing, raw invocation, basic register/authenticate/reset flows, discoverable credential management, and PIN changes against real USB and NFC authenticators.

The current CLI defaults to the first discovered authenticator, supports `--device-id` overrides when needed, accepts either `--format json` or the `--json` shortcut for structured output, and can wait for a disconnected authenticator to reappear in interactive mode before retrying the command.

When `--pin-stdin`, `--old-pin-stdin`, or `--new-pin-stdin` read from an interactive terminal, `fidoctl` now uses no-echo input and converts directly into `client.Secret` bytes.

The current code intentionally stops before vendor-extension handling and hardware-backed integration coverage. Those will land in later stages.

## Architecture direction

The SDK is being built around a strict layered model:

- transport sessions expose raw byte exchange only
- middleware composes tracing, logging, retries, and quirks handling
- protocol-specific packages own CTAP1 and CTAP2 command models separately
- the public client facade remains the only API surface that higher-level tools should consume

## Build and test

```sh
go vet ./...
go test ./...
go run ./cmd/fidoctl devices
go run ./cmd/fidoctl info
printf '%s\n' 123456 | go run ./cmd/fidoctl credentials list --pin-stdin
FIDO_TEST_DEVICE_ID='...' FIDO_TEST_PIN='...' go test -tags=integration ./pkg/client -run TestCredentialLifecycleOnAuthenticator -v
FIDO_TEST_PIN_UV_PROTOCOL2=1 FIDO_TEST_DEVICE_ID='...' FIDO_TEST_PIN='...' go test -tags=integration ./pkg/client -run TestCredentialManagementUsesPINUVAuthProtocol2OnAuthenticator -v
```
