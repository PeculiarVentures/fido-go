//go:build windows

package hid

import (
	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/driver"
	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/windows"
)

func platformEnumerate(strings bool) (driver.Snapshot, error)      { return windows.Enumerate(strings) }
func platformOpen(endpoint driver.Endpoint) (driver.Device, error) { return windows.Open(endpoint) }
