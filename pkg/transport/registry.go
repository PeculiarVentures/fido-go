package transport

import (
	"context"
	"errors"
	"fmt"
)

var (
	errBackendRequired  = errors.New("backend is required")
	errDuplicateBackend = errors.New("backend already registered")
	errBackendNotFound  = errors.New("backend not registered")
)

// Backend discovers and opens sessions for one transport kind.
type Backend interface {
	Kind() Kind
	Discover(ctx context.Context) ([]DeviceDescriptor, error)
	Open(ctx context.Context, device DeviceDescriptor) (Session, error)
}

// Registry coordinates discovery and opening across registered backends.
type Registry struct {
	backends map[Kind]Backend
}

// NewRegistry builds a transport registry from the provided backends.
func NewRegistry(backends ...Backend) (*Registry, error) {
	registry := &Registry{backends: make(map[Kind]Backend, len(backends))}
	for _, backend := range backends {
		if backend == nil {
			return nil, &Error{Op: "new registry", Err: errBackendRequired}
		}
		kind := backend.Kind()
		if kind == "" || kind == KindUnknown {
			return nil, &Error{Op: "new registry", Err: fmt.Errorf("transport: unsupported backend kind %q", kind)}
		}
		if _, exists := registry.backends[kind]; exists {
			return nil, &Error{Op: "new registry", Err: fmt.Errorf("transport: %w: %s", errDuplicateBackend, kind)}
		}
		registry.backends[kind] = backend
	}
	return registry, nil
}

// Discover enumerates descriptors from every registered backend.
func (registry *Registry) Discover(ctx context.Context) ([]DeviceDescriptor, error) {
	var devices []DeviceDescriptor
	for kind, backend := range registry.backends {
		found, err := backend.Discover(ctx)
		if err != nil {
			return nil, &Error{Op: fmt.Sprintf("discover %s devices", kind), Err: err}
		}
		devices = append(devices, found...)
	}
	return devices, nil
}

// Open resolves the backend from the descriptor and opens a session for it.
func (registry *Registry) Open(ctx context.Context, device DeviceDescriptor) (Session, error) {
	backend, ok := registry.backends[device.Transport]
	if !ok {
		return nil, &Error{Op: "open device", Err: fmt.Errorf("transport: %w: %s", errBackendNotFound, device.Transport)}
	}
	return backend.Open(ctx, device)
}
