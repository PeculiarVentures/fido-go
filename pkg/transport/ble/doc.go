// Package ble provides the injectable BLE transport foundation used by tests
// and custom integrations.
//
// The package exposes discovery and fragment-connection hooks plus a
// concurrent-safe session implementation. A production BLE backend can be added
// on top of this foundation later without changing the transport contract.
package ble
