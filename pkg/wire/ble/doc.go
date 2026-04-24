// Package ble provides BLE framing helpers for one ordered fragment stream.
//
// Fragment ordering is guaranteed by the transport/backend. The codec validates
// fragment sizes and the declared aggregate length but does not add its own
// sequence numbers.
package ble
