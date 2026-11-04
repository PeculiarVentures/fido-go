//go:build darwin && cgo

package hid

import (
	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/darwin"
	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/driver"
)

func platformEnumerate(strings bool, _ Filter) (driver.Snapshot, error) {
	return darwin.Enumerate(strings)
}
func platformOpen(endpoint driver.Endpoint) (driver.Device, error) { return darwin.Open(endpoint) }
