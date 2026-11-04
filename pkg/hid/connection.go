package hid

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/driver"
)

type connection struct {
	device              driver.Device
	endpoint            Endpoint
	layout              ReportLayout
	lease               EndpointID
	mu                  sync.Mutex
	retiring            bool
	reason              error
	readBusy, writeBusy bool
	queue               [driver.InputQueueSize]Report
	head, count         int
	ready               chan struct{}
	retired             chan struct{}
	done                chan struct{}
	closeErr            error
	workers             sync.WaitGroup
}

func newConnection(device driver.Device, lease EndpointID) *connection {
	c := &connection{device: device, endpoint: publicEndpoint(device.Endpoint()), layout: publicLayout(device.Layout()), lease: lease, ready: make(chan struct{}, 1), retired: make(chan struct{}), done: make(chan struct{})}
	c.workers.Add(1)
	go c.pump()
	return c
}

// Endpoint returns the actual opened metadata.
func (c *connection) Endpoint() Endpoint { return c.endpoint }

// Layout returns the fixed Input and Output report formats.
func (c *connection) Layout() ReportLayout { return c.layout }

// retireLocked immediately revokes admission. Cleanup alone owns handle closure,
// after every native call has returned; context expiry never releases a lease.
func (c *connection) retireLocked(reason error) {
	if c.retiring {
		return
	}
	c.retiring, c.reason = true, reason
	close(c.retired)
	for i := range c.queue {
		c.queue[i] = Report{}
	}
	c.count = 0
	go func() {
		c.workers.Wait()
		err := c.device.Close()
		shared.releaseEndpoint(c.lease)
		c.mu.Lock()
		c.closeErr = operationError("close", c.endpoint.ID, err)
		close(c.done)
		c.mu.Unlock()
	}()
}

func (c *connection) closedErrorLocked(op string) error {
	if c.reason != nil {
		return operationError(op, c.endpoint.ID, errors.Join(ErrClosed, c.reason))
	}
	return operationError(op, c.endpoint.ID, ErrClosed)
}

func (c *connection) pump() {
	defer c.workers.Done()
	for {
		c.mu.Lock()
		stop := c.retiring
		c.mu.Unlock()
		if stop {
			return
		}
		report, err := c.device.Read(100 * time.Millisecond)
		if err != nil {
			var native *driver.Error
			if errors.As(err, &native) && native.Kind == driver.KindTimeout {
				continue
			}
			c.mu.Lock()
			c.retireLocked(operationError("read", c.endpoint.ID, err))
			c.mu.Unlock()
			return
		}
		c.mu.Lock()
		if c.retiring {
			c.mu.Unlock()
			return
		}
		if report.ID != c.layout.Input.ID || len(report.Data) != c.layout.Input.Size {
			c.retireLocked(operationError("read", c.endpoint.ID, ErrInvalidReport))
			c.mu.Unlock()
			return
		}
		if c.count == len(c.queue) {
			c.retireLocked(operationError("read", c.endpoint.ID, ErrIO))
			c.mu.Unlock()
			return
		}
		// Native implementations may reuse their read buffer on the next poll.
		owned := Report{ID: report.ID, Data: append([]byte(nil), report.Data...)}
		c.queue[(c.head+c.count)%len(c.queue)] = owned
		c.count++
		select {
		case c.ready <- struct{}{}:
		default:
		}
		c.mu.Unlock()
	}
}

// Close initiates retirement even when ctx is already canceled. Repeated calls
// wait for the same cleanup and never close native resources twice.
func (c *connection) Close(ctx context.Context) error {
	c.mu.Lock()
	c.retireLocked(nil)
	if ctx == nil {
		c.mu.Unlock()
		return operationError("close", c.endpoint.ID, ErrInvalidArgument)
	}
	select {
	case <-c.done:
		err := c.closeErr
		c.mu.Unlock()
		return err
	default:
	}
	c.mu.Unlock()
	select {
	case <-c.done:
	case <-ctx.Done():
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.done:
		return c.closeErr
	default:
		return operationError("close", c.endpoint.ID, ctx.Err())
	}
}
