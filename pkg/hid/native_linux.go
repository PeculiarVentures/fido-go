//go:build linux

package hid

import (
	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/driver"
	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/linux"
)

func platformEnumerate(strings bool) (driver.Snapshot, error)      { return linux.Enumerate(strings) }
func platformOpen(endpoint driver.Endpoint) (driver.Device, error) { return linux.Open(endpoint) }
