# Changelog

All notable changes to this project will be documented in this file.

This project follows semantic versioning after `v1.0.0`. While the module is in `v0.x`, public APIs may change between minor releases.

## Unreleased

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
