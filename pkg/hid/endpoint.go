package hid

// EndpointID is an opaque, case-sensitive native endpoint address.
type EndpointID string

// Field distinguishes a known value (including zero) from unavailable metadata.
type Field[T any] struct {
	Value T
	Known bool
}

// Usage identifies an HID usage page and usage.
type Usage struct {
	Page uint16
	ID   uint16
}

// Bus identifies the native transport bus when known.
type Bus uint8

const (
	BusUnknown Bus = iota
	BusUSB
	BusBluetooth
	BusI2C
	BusSPI
	BusOther
)

// Endpoint describes one addressable interface or collection. ID is the
// selector; Path is a diagnostic native locator and need not be unique.
type Endpoint struct {
	ID           EndpointID
	Path         string
	VendorID     Field[uint16]
	ProductID    Field[uint16]
	Usage        Field[Usage]
	Interface    Field[int]
	Bus          Bus
	Serial       Field[string]
	Manufacturer Field[string]
	Product      Field[string]
}

// Filter is a conjunction of exact metadata constraints. Unknown fields do
// not match, and a pointer to zero is distinct from an absent constraint.
type Filter struct {
	VendorID  *uint16
	ProductID *uint16
	Usage     *Usage
	Bus       *Bus
}

// EnumerateOptions controls metadata resolution and inventory selection.
type EnumerateOptions struct {
	Filter         Filter
	ResolveStrings bool
}

// Snapshot is an inventory observation. Complete means no known omissions,
// rather than an atomic observation of the physical world.
type Snapshot struct {
	Endpoints []Endpoint
	Complete  bool
	Warnings  []error
}
