package hid

import (
	"context"
	"time"

	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/driver"
)

// Backend enumerates endpoints and opens an exact endpoint address.
type Backend interface {
	Enumerate(context.Context, EnumerateOptions) (Snapshot, error)
	Open(context.Context, Endpoint) (Conn, error)
}

// Native is the platform HID backend. Its zero value is ready for use; all
// instances share resource admission and endpoint exclusion.
type Native struct {
	enumerate func(bool) (driver.Snapshot, error)
	open      func(driver.Endpoint) (driver.Device, error)
}

// New creates a platform backend without performing native I/O.
func New() *Native { return &Native{} }

// Conn owns one opened collection. One Read and one Write may overlap.
// Context cancellation after admission retires the connection. Close waits
// for native completion; an expired Close leaves the supervisor owning cleanup.
type Conn interface {
	Endpoint() Endpoint
	Layout() ReportLayout
	Read(context.Context, time.Duration) (Report, error)
	Write(context.Context, Report) (WriteResult, error)
	Close(context.Context) error
}

var _ Backend = (*Native)(nil)
var _ Conn = (*connection)(nil)
