package hid

import (
	"context"
	"errors"
	"sync"

	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/driver"
)

// Enumerate observes the selected inventory. A canceled caller returns promptly,
// while its bounded native worker retains ownership until actual completion.
func (n *Native) Enumerate(ctx context.Context, options EnumerateOptions) (Snapshot, error) {
	if ctx == nil {
		return Snapshot{}, operationError("enumerate", "", ErrInvalidArgument)
	}
	options.Filter = cloneFilter(options.Filter)
	if err := ctx.Err(); err != nil {
		return Snapshot{}, operationError("enumerate", "", err)
	}
	if err := shared.reserveEnumeration(); err != nil {
		return Snapshot{}, operationError("enumerate", "", err)
	}
	enumerate := func(resolveStrings bool) (driver.Snapshot, error) {
		return platformEnumerate(resolveStrings, options.Filter)
	}
	if n != nil && n.enumerate != nil {
		enumerate = n.enumerate
	}
	var mu sync.Mutex
	var result Snapshot
	var resultErr error
	completed := false
	done := make(chan struct{})
	go func() {
		raw, err := enumerate(options.ResolveStrings)
		if len(raw.Endpoints) > driver.MaxInventoryEndpoints {
			raw.Endpoints = raw.Endpoints[:driver.MaxInventoryEndpoints]
			raw.Complete = false
			err = errors.Join(err, ErrResourceLimit)
		}
		if len(raw.Warnings) > driver.MaxInventoryEndpoints {
			raw.Warnings = raw.Warnings[:driver.MaxInventoryEndpoints]
			raw.Complete = false
			err = errors.Join(err, ErrResourceLimit)
		}
		snapshot := Snapshot{Complete: raw.Complete, Endpoints: make([]Endpoint, 0, len(raw.Endpoints)), Warnings: make([]error, 0, len(raw.Warnings))}
		for _, warning := range raw.Warnings {
			if warning != nil {
				snapshot.Warnings = append(snapshot.Warnings, operationError("enumerate", "", warning))
			}
		}
		for _, item := range raw.Endpoints {
			endpoint := publicEndpoint(item)
			if !options.ResolveStrings {
				endpoint.Serial = Field[string]{}
				endpoint.Manufacturer = Field[string]{}
				endpoint.Product = Field[string]{}
			}
			match, unknown := matchFilter(endpoint, options.Filter)
			if unknown {
				snapshot.Complete = false
				snapshot.Warnings = append(snapshot.Warnings, operationError("filter", endpoint.ID, ErrIO))
			}
			if match {
				snapshot.Endpoints = append(snapshot.Endpoints, endpoint)
			}
		}
		if err != nil {
			snapshot.Complete = false
		}
		shared.releaseEnumeration()
		mu.Lock()
		result, resultErr, completed = snapshot, operationError("enumerate", "", err), true
		close(done)
		mu.Unlock()
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
	mu.Lock()
	defer mu.Unlock()
	if completed {
		return result, resultErr
	}
	return Snapshot{}, operationError("enumerate", "", ctx.Err())
}

// Open opens exactly endpoint.ID and validates the actual opened metadata.
// Cancellation of a pending Open leaves its native worker owning late cleanup.
func (n *Native) Open(ctx context.Context, endpoint Endpoint) (Conn, error) {
	if ctx == nil || endpoint.ID == "" || !boundedEndpoint(endpoint) {
		return nil, operationError("open", endpoint.ID, ErrInvalidArgument)
	}
	if err := ctx.Err(); err != nil {
		return nil, operationError("open", endpoint.ID, err)
	}
	if err := shared.reserveEndpoint(endpoint.ID); err != nil {
		return nil, operationError("open", endpoint.ID, err)
	}
	open := platformOpen
	if n != nil && n.open != nil {
		open = n.open
	}
	var mu sync.Mutex
	var result Conn
	var resultErr error
	completed, abandoned := false, false
	done := make(chan struct{})
	go func() {
		device, err := open(nativeEndpoint(endpoint))
		if err == nil && device == nil {
			err = ErrIO
		}
		if err == nil && !matchesEndpoint(endpoint, publicEndpoint(device.Endpoint())) {
			err = ErrStaleEndpoint
		}
		if err == nil {
			layout := device.Layout()
			if layout.Input.Size <= 0 || layout.Output.Size <= 0 || layout.Input.Size > driver.MaxReportSize || layout.Output.Size > driver.MaxReportSize {
				err = ErrUnsupported
			}
		}
		mu.Lock()
		if abandoned || err != nil {
			mu.Unlock()
			if device != nil {
				err = errors.Join(err, device.Close())
			}
			shared.releaseEndpoint(endpoint.ID)
			mu.Lock()
			resultErr, completed = operationError("open", endpoint.ID, err), true
			close(done)
			mu.Unlock()
			return
		}
		result = newConnection(device, endpoint.ID)
		completed = true
		close(done)
		mu.Unlock()
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
	mu.Lock()
	defer mu.Unlock()
	if completed {
		return result, resultErr
	}
	abandoned = true
	return nil, operationError("open", endpoint.ID, ctx.Err())
}
