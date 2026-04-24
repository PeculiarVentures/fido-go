# Contributing

## Project Status

`fido-go` is in active `v0` development. Public APIs are expected to evolve until `v1.0.0`, but changes should preserve the layered architecture described in README and `.github/copilot-instructions.md`.

## Development Requirements

- Go version from `go.mod`.
- CGO enabled.
- Linux builds require `pkg-config`, `libpcsclite-dev`, and `libudev-dev`.
- macOS builds use the system PC/SC, IOKit, and CoreFoundation frameworks.

## Local Checks

Run these before opening a pull request:

```sh
go mod tidy -diff
go vet ./...
go test ./...
go test -race ./...
go test -cover ./...
go build -o /tmp/fidoctl ./cmd/fidoctl
```

## Integration Tests

Hardware tests are opt-in and must not run during normal unit tests.

```sh
FIDO_TEST_DEVICE_ID='...' FIDO_TEST_PIN='...' go test -tags=integration ./pkg/client -run TestCredentialLifecycleOnAuthenticator -v
FIDO_TEST_PIN_UV_PROTOCOL2=1 FIDO_TEST_DEVICE_ID='...' FIDO_TEST_PIN='...' go test -tags=integration ./pkg/client -run TestCredentialManagementUsesPINUVAuthProtocol2OnAuthenticator -v
```

Use a test authenticator only. Credential lifecycle and reset-style tests can modify authenticator state.

## Architecture Rules

- Transport packages are protocol-agnostic and expose raw byte exchange only.
- Wire packages handle framing only.
- CTAP1 and CTAP2 command models stay separate.
- CLI code accesses authenticators through the public `pkg/client` facade.
- Raw access through `Client.InvokeRaw(ctx, family, command, payload)` must remain available.
- PIN-like values should use `client.Secret` and be wiped by callers when possible.

## Pull Requests

- Keep changes focused.
- Add or update tests at the layer that owns the behavior.
- Update README, changelog, and relevant docs when public behavior changes.
- Do not include raw FIDO spec mirrors from `docs/raw/fido`; they are intentionally ignored and fetched on demand.
