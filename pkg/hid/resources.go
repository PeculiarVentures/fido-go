package hid

import (
	"sync"
)

const (
	maxConnections = 64
	maxNativeBytes = 64 * 1024 * 1024
	// Cover both the native callback ring and Go queue (64 reports each),
	// temporary native/Go reports, two descriptor copies, and fixed overhead.
	// The rounded reservation is made before starting native Open.
	connectionBytes = 768 * 1024
	// Enumeration holds at most 128 native device records/descriptors,
	// 1024 collection endpoints and bounded metadata/parser scratch storage.
	enumerationBytes = 16 * 1024 * 1024
)

type resources struct {
	mu          sync.Mutex
	endpoints   map[EndpointID]bool
	bytes       int
	enumerating bool
}

var shared = resources{endpoints: make(map[EndpointID]bool)}

func (r *resources) reserveEndpoint(id EndpointID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.endpoints[id] {
		return ErrBusy
	}
	if len(r.endpoints) >= maxConnections || r.bytes > maxNativeBytes-connectionBytes {
		return ErrResourceLimit
	}
	r.endpoints[id] = true
	r.bytes += connectionBytes
	return nil
}
func (r *resources) releaseEndpoint(id EndpointID) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.endpoints, id)
	r.bytes -= connectionBytes
}
func (r *resources) reserveEnumeration() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.enumerating || r.bytes > maxNativeBytes-enumerationBytes {
		return ErrResourceLimit
	}
	r.enumerating = true
	r.bytes += enumerationBytes
	return nil
}
func (r *resources) releaseEnumeration() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.enumerating = false
	r.bytes -= enumerationBytes
}
