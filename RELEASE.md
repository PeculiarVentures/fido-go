# Release Process

`fido-go` uses `v0.x` tags while the public API is experimental. Breaking API changes may happen between minor `v0` releases and must be called out in `CHANGELOG.md`.

## Versioning

- Use semantic version tags: `v0.1.0`, `v0.2.0`, and so on.
- Reserve `v1.0.0` for the first stable API release.
- Do not tag a release from a commit with failing CI.

## Pre-Release Checklist

Before creating a public tag:

1. Confirm GitHub Actions CI passes on the target commit.
2. Run or review the CI results for:
   - `go mod tidy -diff`
   - `go vet ./...`
   - `go test ./...`
   - `go test -race ./...`
   - `go test -cover ./...`
   - `go build -o /tmp/fidoctl ./cmd/fidoctl`
3. Run hardware smoke tests when the release changes transport, PIN, credential, or reset behavior.
4. Move `CHANGELOG.md` entries from `Unreleased` to the target version.
5. Verify README feature matrix and known limitations are current.
6. Confirm `LICENSE`, `SECURITY.md`, and `CONTRIBUTING.md` are still accurate.

## Optional Hardware Smoke Tests

Use a dedicated test authenticator only.

```sh
FIDO_TEST_DEVICE_ID='...' FIDO_TEST_PIN='...' go test -tags=integration ./pkg/client -run TestCredentialLifecycleOnAuthenticator -v
FIDO_TEST_PIN_UV_PROTOCOL2=1 FIDO_TEST_DEVICE_ID='...' FIDO_TEST_PIN='...' go test -tags=integration ./pkg/client -run TestCredentialManagementUsesPINUVAuthProtocol2OnAuthenticator -v
```

## Tagging

```sh
git tag v0.1.0
git push origin v0.1.0
```

After pushing, confirm the tag CI run completes successfully.
