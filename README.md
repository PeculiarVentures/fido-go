# fido-go

![CI](https://github.com/PeculiarVentures/fido-go/actions/workflows/ci.yml/badge.svg)

`fido-go` is a Go SDK for working with FIDO authenticators with strict separation between transport, framing, CTAP protocol logic, and public client APIs.

## Status

`fido-go` is an experimental `v0` SDK and CLI. It is suitable for early integration, protocol work, and feedback, but public APIs may change before `v1.0.0`.

Current limitations:

- production BLE discovery/connection backend is not included yet
- CTAP2 bio enrollment enumeration is not implemented yet
- NFC uses chained short APDUs; extended APDUs are not implemented yet
- hardware-backed integration coverage is opt-in and requires a real authenticator
- vendor-extension handling is still planned

## Current coverage

The current implementation covers the first six stages of the roadmap:

- `pkg/protocol` defines protocol-family primitives shared by the public API.
- `pkg/transport` defines the transport-agnostic session contract and device descriptor.
- `pkg/middleware` defines the exchange middleware pipeline for tracing, logging, retries, and vendor quirks.
- `pkg/client` defines the public client facade for raw protocol dispatch and capability probing.
- `pkg/ctap1` implements the `U2F_VERSION` command and APDU helpers used for CTAP1 capability detection.
- `pkg/ctap1` also implements typed `U2F_REGISTER` and `U2F_AUTHENTICATE` command encoding/decoding.
- `pkg/ctap2` implements the `authenticatorGetInfo (0x04)` command and capability response decoding.
- `pkg/ctap2` also provides typed foundations for `authenticatorMakeCredential`, `authenticatorGetAssertion`, `authenticatorClientPIN`, `authenticatorCredentialManagement`, and `authenticatorReset`.
- `pkg/wire` provides protocol-agnostic framing foundations for USB HID, NFC/APDU, and BLE packetization.
- `pkg/transport` provides a backend registry, injectable transport backends, a real USB HID backend, a PC/SC-backed NFC backend, and a documented BLE foundation for custom backends while a production BLE implementation is still pending.
- `pkg/client` now also exposes discovery, tracing, register/authenticate/reset helpers, resident-key registration controls, discoverable-credential enumeration and deletion, and CTAP2 PIN changes for user-facing tooling.
- `cmd/fidoctl` provides a Cobra-based CLI for device discovery, capability inspection, tracing, raw invocation, basic register/authenticate/reset flows, discoverable credential management, and PIN changes against real USB authenticators, with NFC/PCSC discovery available via `--nfc`.

The current CLI defaults to USB HID discovery, supports `--device-id` overrides when needed, accepts either `--format json` or the `--json` shortcut for structured output, can opt into NFC/PCSC discovery with `--nfc`, and can wait for a disconnected authenticator to reappear in interactive mode before retrying the command.

When `--pin-stdin`, `--old-pin-stdin`, or `--new-pin-stdin` read from an interactive terminal, `fidoctl` now uses no-echo input and converts directly into `client.Secret` bytes.

The current code intentionally keeps advanced vendor-extension handling and broader hardware-backed integration coverage for later stages.

## Feature matrix

| Area | Status |
| --- | --- |
| Public client facade | Implemented |
| CTAP1 version/register/authenticate | Implemented |
| CTAP2 getInfo/makeCredential/getAssertion/reset foundations | Implemented |
| CTAP2 ClientPIN protocol 1 and 2 flows | Implemented |
| CTAP2 credential management list/delete facade | Implemented |
| CTAP2 bio enrollment enumeration | Not implemented |
| USB HID transport | Implemented |
| NFC/PCSC transport | Implemented with short APDU chaining |
| NFC extended APDU support | Not implemented |
| BLE transport | Custom-backend foundation only |
| CLI `fidoctl` | Implemented for discovery, info, raw, trace, register, authenticate, reset, credentials, and PIN operations |
| Hardware integration tests | Opt-in with `-tags=integration` |

## Architecture direction

The SDK is being built around a strict layered model:

- transport sessions expose raw byte exchange only
- middleware composes tracing, logging, retries, and quirks handling
- protocol-specific packages own CTAP1 and CTAP2 command models separately
- the public client facade remains the only API surface that higher-level tools should consume

## Build and test

```sh
go mod tidy -diff
go vet ./...
go test ./...
go test -race ./...
go test -cover ./...
go build -o /tmp/fidoctl ./cmd/fidoctl
go run ./cmd/fidoctl devices
go run ./cmd/fidoctl info
printf '%s\n' 123456 | go run ./cmd/fidoctl credentials list --pin-stdin
FIDO_TEST_DEVICE_ID='...' FIDO_TEST_PIN='...' go test -tags=integration ./pkg/client -run TestCredentialLifecycleOnAuthenticator -v
FIDO_TEST_PIN_UV_PROTOCOL2=1 FIDO_TEST_DEVICE_ID='...' FIDO_TEST_PIN='...' go test -tags=integration ./pkg/client -run TestCredentialManagementUsesPINUVAuthProtocol2OnAuthenticator -v
```

Linux builds require `pkg-config`, `libpcsclite-dev`, and `libudev-dev` for the NFC/PCSC and HID CGO dependencies.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) for development workflow and integration test requirements.

Report suspected vulnerabilities privately according to [SECURITY.md](SECURITY.md).

See [RELEASE.md](RELEASE.md) for the release checklist and `v0` versioning policy.

## License

Licensed under the [MIT License](LICENSE).
