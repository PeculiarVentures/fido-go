# Changelog

All notable changes to this project will be documented in this file.

This project follows semantic versioning after `v1.0.0`. While the module is in `v0.x`, public APIs may change between minor releases.

## Unreleased

## v0.5.0 - 2026-11-04

### Added

- Public `pkg/hid` APIs for native HID inventory, endpoint metadata, report layouts, and Input/Output report exchanges on macOS, Windows, and Linux.
- Injectable HID backends for production USB sessions, typed `usb.ExchangeError` delivery evidence, and optional `transport.ContextCloser` / `client.ContextCloser` cleanup interfaces.
- Extensible diagnostic harnesses with validated JSON evidence for HID/native behavior, production USB sessions, and client/CTAP2 qualification. Native injection hooks require `hid_diagnostics`; physical-device, operator-assisted, and credential/PIN/reset checks require their respective explicit opt-ins.

### Changed

- USB HID transport now uses the native backends instead of `go-hid`/HIDAPI. Inventory distinguishes unknown metadata from observed values and tracks snapshot completeness.
- Diagnostic CI now checks integration builds, configurations without cgo, and supported platform combinations, with separate evidence for native, USB-session, and client layers.

### Fixed

- macOS report writes now protect the native call with scoped SIGURG masking, preserve mask-restoration and delivery errors, and retire damaged writers without reusing their generation.
- Cancellation and Close retain ownership of in-flight native operations until cleanup completes, prevent retiring endpoint reuse, and isolate late input from reopened sessions.
- Concurrent native enumerations now queue within their caller's context instead of failing immediately. Unsupported unrelated report collections no longer make an otherwise qualified FIDO inventory incomplete.

### Migration notes

- USB endpoint IDs now identify exact native interfaces or application collections. Rediscover devices instead of reusing saved HIDAPI IDs. VID/PID-only Open and fallback to another matching device have been removed; legacy path-only selection requires an unambiguous complete inventory.
- USB `Close()` now waits up to 250 ms for cleanup and can return a deadline error while native ownership is retained. Use the optional `CloseContext` interfaces when a different cleanup budget is required.
- Each USB Output report write now has a five-second maximum wait, also bounded by the caller's context. A timeout can leave delivery uncertain; it does not authorize replaying the application request.

## v0.4.0 - 2026-10-22

### Added

- Explicit CTAPHID message exchange through optional `client.HIDClient` / `usb.HIDSession` interfaces and `client.ExchangeHID`, preserving existing CTAP1/CTAP2 APIs.
- Separate HID middleware and trace events with complete payload redaction by default, plus a read-only Yubico `READ_CONFIG` example.

### Fixed

- Queued USB exchanges now honor context cancellation without interrupting an active exchange, and native HID close/cancellation safely coordinate device ownership.
- Native HID handle cleanup now waits for active native calls, preventing use-after-close during concurrent exchange, cancellation, and `Close`. Reads use bounded polling; cancellation returns promptly while cleanup completes safely, and repeated `Close` reports the same cleanup result.
- Raw and typed CTAP1 `VERSION` commands now use extended APDU encoding accepted by USB HID authenticators. Explicit short APDU encoding remains available.
- USB HID initialization now ignores reports from other channels and unrelated INIT nonces, validates the allocated channel, and probes readiness before sending application requests. Bounded handshake retries use fresh channels to recover after interrupted exchanges without replaying application commands or accepting stale readiness replies.

## v0.3.0 - 2026-05-19

### Added

- CTAP2 credential management list and delete flows now support built-in UV authorization on authenticators that advertise stable credential-management capabilities.

### Fixed

- Built-in UV credential management no longer falls back to preview-scoped commands when the authenticator requires the stable credential-management command set.
- Credential management now consistently reuses authenticator-reported built-in UV capability checks across authorization flows.

## v0.2.0 - 2026-05-04

### Added

- `fidoctl --nfc` to opt into NFC/PCSC discovery alongside USB HID.
- `pkg/client.NewDefaultLocator` transport options for explicit USB and NFC discovery preferences.

### Changed

- Default locator discovery now enables USB HID only unless NFC is explicitly requested.
- The CLI now configures transport preference through the public client facade instead of probing NFC by default.

## v0.1.0 - 2026-04-24

### Added

- Initial FIDO SDK package structure with CTAP1, CTAP2, transport, wire, middleware, public client facade, and `fidoctl` CLI.
- USB HID and NFC/PCSC transport backends.
- BLE transport foundation for custom discovery and connection implementations.
- Unit test coverage for protocol encoding/decoding, transport abstractions, wire codecs, client flows, and CLI command behavior.
- Integration tests for hardware credential lifecycle flows behind the `integration` build tag.
- GitHub Actions CI for tidy, vet, test, race test, coverage smoke test, and CLI build.

### Fixed

- Retried interactive CTAP2 reset after the authenticator reports `not allowed`, allowing YubiKey reset flows to complete after reinsert/retap inside the reset window.

### Known Limitations

- APIs are experimental until the first `v1.0.0` release.
- Production BLE discovery/connection backend is not included yet.
- CTAP2 bio enrollment enumeration is not implemented yet.
- NFC uses chained short APDUs; extended APDUs are not implemented yet.
- Hardware-backed integration coverage requires real authenticators and explicit environment variables.
