package hid

import (
	"context"
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
	mu        sync.Mutex
	endpoints map[EndpointID]bool
	bytes     int
	// enumeration is a one-slot semaphore. Concurrent callers queue for it
	// under their own context instead of failing while another inventory runs.
	enumeration chan struct{}
}

var shared = resources{endpoints: make(map[EndpointID]bool), enumeration: make(chan struct{}, 1)}

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

// reserveEnumeration waits for the single native inventory slot. Abandoned
// enumerations keep the slot until their native worker completes, so a waiter
// never overlaps native traversal. Only the memory budget fails immediately.
func (r *resources) reserveEnumeration(ctx context.Context) error {
	select {
	case r.enumeration <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.bytes > maxNativeBytes-enumerationBytes {
		<-r.enumeration
		return ErrResourceLimit
	}
	r.bytes += enumerationBytes
	return nil
}
func (r *resources) releaseEnumeration() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.bytes -= enumerationBytes
	<-r.enumeration
}
