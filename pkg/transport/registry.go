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
	order    []Kind
}

// NewRegistry builds a transport registry from the provided backends.
func NewRegistry(backends ...Backend) (*Registry, error) {
	registry := &Registry{backends: make(map[Kind]Backend, len(backends)), order: make([]Kind, 0, len(backends))}
	for _, backend := range backends {
		if backend == nil {
			return nil, Wrap("new registry", errBackendRequired)
		}
		kind := backend.Kind()
		if kind == "" || kind == KindUnknown {
			return nil, Wrap("new registry", Unsupported(fmt.Errorf("transport: unsupported backend kind %q", kind)))
		}
		if _, exists := registry.backends[kind]; exists {
			return nil, Wrap("new registry", fmt.Errorf("transport: %w: %s", errDuplicateBackend, kind))
		}
		registry.backends[kind] = backend
		registry.order = append(registry.order, kind)
	}
	return registry, nil
}

// Discover enumerates descriptors from every registered backend.
func (registry *Registry) Discover(ctx context.Context) ([]DeviceDescriptor, error) {
	var (
		devices []DeviceDescriptor
		errs    []error
	)
	for _, kind := range registry.order {
		backend := registry.backends[kind]
		found, err := backend.Discover(ctx)
		if err != nil {
			errs = append(errs, Wrap(fmt.Sprintf("discover %s devices", kind), err))
			continue
		}
		devices = append(devices, found...)
	}
	if len(errs) > 0 {
		return devices, errors.Join(errs...)
	}
	return devices, nil
}

// Open resolves the backend from the descriptor and opens a session for it.
func (registry *Registry) Open(ctx context.Context, device DeviceDescriptor) (Session, error) {
	backend, ok := registry.backends[device.Transport]
	if !ok {
		return nil, Wrap("open device", Unsupported(fmt.Errorf("transport: %w: %s", errBackendNotFound, device.Transport)))
	}
	return backend.Open(ctx, device)
}
