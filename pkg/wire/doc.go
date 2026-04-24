// Package wire documents the transport-specific framing packages used by the
// SDK.
//
// The root package does not expose framing APIs directly. Callers should use
// the transport-specific subpackages:
//
//   - wire/hid for CTAPHID packet framing
//   - wire/nfc for chained APDU framing
//   - wire/ble for BLE fragment framing
package wire
