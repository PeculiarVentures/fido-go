// Package driver defines the private contract between HID native bindings and
// the public package's resource and cancellation supervisor.
package driver

import "time"

const (
	MaxDescriptorSize     = 64 * 1024
	MaxReportSize         = 4096
	InputQueueSize        = 64
	MaxInventoryDevices   = 128
	MaxInventoryEndpoints = 1024
	MaxMetadataSize       = 4096
)

type Field[T any] struct {
	Value T
	Known bool
}
type Usage struct{ Page, ID uint16 }
type Bus uint8

const (
	BusUnknown Bus = iota
	BusUSB
	BusBluetooth
	BusI2C
	BusSPI
	BusOther
)

type Endpoint struct {
	ID                            string
	Path                          string
	VendorID, ProductID           Field[uint16]
	Usage                         Field[Usage]
	Interface                     Field[int]
	Bus                           Bus
	Serial, Manufacturer, Product Field[string]
}
type Snapshot struct {
	Endpoints []Endpoint
	Complete  bool
	Warnings  []error
}
type ReportSpec struct {
	ID   uint8
	Size int
}
type Layout struct{ Input, Output ReportSpec }
type Report struct {
	ID   uint8
	Data []byte
}
type Outcome uint8

const (
	OutcomeUnknown Outcome = iota
	OutcomeNotSubmitted
	OutcomeCompleted
)

type WriteResult struct{ Outcome Outcome }

// Device permits one Read and one Write concurrently. Close is called only
// after both have returned. Read's local timeout must leave no pending read
// that can consume the next caller's report. Native buffers live to completion.
type Device interface {
	Endpoint() Endpoint
	Layout() Layout
	Read(time.Duration) (Report, error)
	Write(Report) (WriteResult, error)
	Close() error
}

type Kind uint8

const (
	KindIO Kind = iota
	KindClosed
	KindRemoved
	KindPermission
	KindBusy
	KindUnsupported
	KindInvalidArgument
	KindInvalidReport
	KindStaleEndpoint
	KindTimeout
	KindResourceLimit
)

// Error retains platform codes without interpreting command delivery.
type Error struct {
	Op      string
	Kind    Kind
	Domain  string
	Code    uint64
	Message string
	Cause   error
}

func (e *Error) Error() string {
	if e.Message != "" {
		return "hid native: " + e.Op + ": " + e.Message
	}
	if e.Cause != nil {
		return "hid native: " + e.Op + ": " + e.Cause.Error()
	}
	return "hid native: " + e.Op
}
func (e *Error) Unwrap() error { return e.Cause }
