package hid

import (
	"context"
	"time"
)

// Read waits for one independently owned report. A positive local wait expires
// without retiring the connection; context cancellation after admission retires it.
func (c *connection) Read(ctx context.Context, wait time.Duration) (Report, error) {
	if ctx == nil || wait < 0 {
		return Report{}, operationError("read", c.endpoint.ID, ErrInvalidArgument)
	}
	if err := ctx.Err(); err != nil {
		return Report{}, operationError("read", c.endpoint.ID, err)
	}
	c.mu.Lock()
	if err := ctx.Err(); err != nil {
		c.mu.Unlock()
		return Report{}, operationError("read", c.endpoint.ID, err)
	}
	if c.retiring {
		err := c.closedErrorLocked("read")
		c.mu.Unlock()
		return Report{}, err
	}
	if c.readBusy {
		c.mu.Unlock()
		return Report{}, operationError("read", c.endpoint.ID, ErrBusy)
	}
	c.readBusy = true
	c.mu.Unlock()
	defer func() { c.mu.Lock(); c.readBusy = false; c.mu.Unlock() }()
	var timer *time.Timer
	var timeout <-chan time.Time
	if wait > 0 {
		timer = time.NewTimer(wait)
		timeout = timer.C
		defer timer.Stop()
	}
	var wakeError error
	for {
		c.mu.Lock()
		// Once cancellation is observed for this admitted read it wins over
		// queued input; a local wait timeout does not revoke the connection.
		if err := ctx.Err(); err != nil {
			c.retireLocked(operationError("read", c.endpoint.ID, err))
			c.mu.Unlock()
			return Report{}, operationError("read", c.endpoint.ID, err)
		}
		if c.retiring {
			err := c.closedErrorLocked("read")
			c.mu.Unlock()
			return Report{}, err
		}
		if c.count > 0 {
			report := c.queue[c.head]
			c.queue[c.head] = Report{}
			c.head = (c.head + 1) % len(c.queue)
			c.count--
			c.mu.Unlock()
			return report, nil
		}
		if wakeError != nil {
			if wakeError != ErrTimeout {
				c.retireLocked(operationError("read", c.endpoint.ID, wakeError))
			}
			c.mu.Unlock()
			return Report{}, operationError("read", c.endpoint.ID, wakeError)
		}
		c.mu.Unlock()
		select {
		case <-c.ready:
		case <-c.retired:
		case <-ctx.Done():
			wakeError = ctx.Err()
		case <-timeout:
			wakeError = ErrTimeout
		}
	}
}
