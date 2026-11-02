//go:build (!darwin && !linux && !windows) || (darwin && !cgo)

package hid

import "github.com/PeculiarVentures/fido-go/pkg/hid/internal/driver"

func platformEnumerate(bool, Filter) (driver.Snapshot, error) {
	return driver.Snapshot{}, ErrUnsupported
}
func platformOpen(driver.Endpoint) (driver.Device, error) { return nil, ErrUnsupported }
