package hid

import (
	"context"
	"errors"

	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/driver"
)

type pendingWrite struct {
	done      chan struct{}
	completed bool
	submitted bool
	result    WriteResult
	err       error
}

// Write copies valid report data before native submission. Cancellation returns
// promptly while the native worker retains the copy until actual completion.
func (c *connection) Write(ctx context.Context, report Report) (WriteResult, error) {
	rejected := WriteResult{Outcome: OutcomeNotSubmitted}
	if ctx == nil {
		return rejected, operationError("write", c.endpoint.ID, ErrInvalidArgument)
	}
	if err := ctx.Err(); err != nil {
		return rejected, operationError("write", c.endpoint.ID, err)
	}
	if report.ID != c.layout.Output.ID || len(report.Data) != c.layout.Output.Size {
		return rejected, operationError("write", c.endpoint.ID, ErrInvalidReport)
	}
	c.mu.Lock()
	if err := ctx.Err(); err != nil {
		c.mu.Unlock()
		return rejected, operationError("write", c.endpoint.ID, err)
	}
	if c.retiring {
		err := c.closedErrorLocked("write")
		c.mu.Unlock()
		return rejected, err
	}
	if c.writeBusy {
		c.mu.Unlock()
		return rejected, operationError("write", c.endpoint.ID, ErrBusy)
	}
	c.writeBusy = true
	owned := driver.Report{ID: report.ID, Data: append([]byte(nil), report.Data...)}
	pending := &pendingWrite{done: make(chan struct{})}
	c.workers.Add(1)
	go c.performWrite(ctx, pending, owned)
	c.mu.Unlock()
	defer func() { c.mu.Lock(); c.writeBusy = false; c.mu.Unlock() }()
	select {
	case <-pending.done:
	case <-ctx.Done():
	case <-c.retired:
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if pending.completed {
		// Preserve confirmed native completion while retiring an operation
		// whose caller observed cancellation before returning.
		if err := ctx.Err(); err != nil {
			c.retireLocked(operationError("write", c.endpoint.ID, err))
			return pending.result, operationError("write", c.endpoint.ID, errors.Join(pending.err, err))
		}
		return pending.result, pending.err
	}
	if err := ctx.Err(); err != nil {
		c.retireLocked(operationError("write", c.endpoint.ID, err))
		result := WriteResult{}
		if !pending.submitted {
			result.Outcome = OutcomeNotSubmitted
		}
		return result, operationError("write", c.endpoint.ID, err)
	}
	return WriteResult{}, c.closedErrorLocked("write")
}

func (c *connection) performWrite(ctx context.Context, pending *pendingWrite, report driver.Report) {
	defer c.workers.Done()
	c.mu.Lock()
	if err := ctx.Err(); err != nil {
		c.retireLocked(operationError("write", c.endpoint.ID, err))
	}
	if c.retiring {
		pending.result, pending.err, pending.completed = WriteResult{Outcome: OutcomeNotSubmitted}, c.closedErrorLocked("write"), true
		close(pending.done)
		c.mu.Unlock()
		return
	}
	// Submission is linearized under the same mutex as retirement. The
	// worker owns its buffer from here until the native call has completed.
	pending.submitted = true
	c.mu.Unlock()
	raw, err := c.device.Write(report)
	result := WriteResult{Outcome: WriteOutcome(raw.Outcome)}
	if raw.Outcome > driver.OutcomeCompleted {
		result.Outcome = OutcomeUnknown
		err = errors.Join(err, ErrIO)
	}
	if err == nil && result.Outcome != OutcomeCompleted {
		err = ErrIO
	}
	c.mu.Lock()
	pending.result, pending.err, pending.completed = result, operationError("write", c.endpoint.ID, err), true
	close(pending.done)
	if err != nil {
		c.retireLocked(pending.err)
	}
	c.mu.Unlock()
}
