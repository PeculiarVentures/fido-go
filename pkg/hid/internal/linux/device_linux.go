//go:build linux

package linux

import (
	"errors"
	"time"

	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/driver"
	"golang.org/x/sys/unix"
)

type device struct {
	fd       int
	endpoint driver.Endpoint
	layout   driver.Layout
}

func matches(want, got driver.Endpoint) bool {
	return (!want.VendorID.Known || got.VendorID == want.VendorID) && (!want.ProductID.Known || got.ProductID == want.ProductID) && (!want.Usage.Known || got.Usage == want.Usage) && (!want.Interface.Known || got.Interface == want.Interface) && (want.Bus == driver.BusUnknown || got.Bus == want.Bus) && (!want.Serial.Known || got.Serial == want.Serial) && (!want.Manufacturer.Known || got.Manufacturer == want.Manufacturer) && (!want.Product.Known || got.Product == want.Product)
}

// Endpoint returns metadata checked against the open fd.
func (d *device) Endpoint() driver.Endpoint { return d.endpoint }

// Layout returns the descriptor's exact report sizes.
func (d *device) Layout() driver.Layout { return d.layout }

// Read uses a nonblocking fd; a local timeout leaves no pending native read.
func (d *device) Read(wait time.Duration) (driver.Report, error) {
	if wait < 0 {
		return driver.Report{}, &driver.Error{Op: "read", Kind: driver.KindInvalidArgument}
	}
	var deadline time.Time
	if wait > 0 {
		deadline = time.Now().Add(wait)
	}
	// Read one byte beyond every legal native report to detect oversize input.
	buffer := make([]byte, driver.MaxReportSize+2)
	for {
		timeout := -1
		if !deadline.IsZero() {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return driver.Report{}, &driver.Error{Op: "read", Kind: driver.KindTimeout}
			}
			milliseconds := remaining / time.Millisecond
			if remaining%time.Millisecond != 0 {
				milliseconds++
			}
			if milliseconds > 2147483647 {
				milliseconds = 2147483647
			}
			timeout = int(milliseconds)
		}
		poll := []unix.PollFd{{Fd: int32(d.fd), Events: unix.POLLIN}}
		n, err := unix.Poll(poll, timeout)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return driver.Report{}, nativeError("poll", err)
		}
		if n == 0 {
			return driver.Report{}, &driver.Error{Op: "read", Kind: driver.KindTimeout}
		}
		if poll[0].Revents&unix.POLLNVAL != 0 {
			return driver.Report{}, nativeError("poll", unix.EBADF)
		}
		if poll[0].Revents&unix.POLLIN == 0 {
			if poll[0].Revents&unix.POLLHUP != 0 {
				return driver.Report{}, nativeError("poll", unix.ENODEV)
			}
			return driver.Report{}, nativeError("poll", unix.EIO)
		}
		n, err = unix.Read(d.fd, buffer)
		if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) {
			continue
		}
		if err != nil {
			return driver.Report{}, nativeError("read", err)
		}
		if n == 0 {
			return driver.Report{}, nativeError("read", unix.ENODEV)
		}
		data := buffer[:n]
		if d.layout.Input.ID != 0 {
			if data[0] != d.layout.Input.ID {
				continue
			}
			data = data[1:]
		}
		if len(data) != d.layout.Input.Size {
			return driver.Report{}, &driver.Error{Op: "read", Kind: driver.KindInvalidReport, Message: "native input length differs from descriptor"}
		}
		return driver.Report{ID: d.layout.Input.ID, Data: append([]byte(nil), data...)}, nil
	}
}

// Write submits a single complete hidraw report and never retries ambiguous I/O.
func (d *device) Write(report driver.Report) (driver.WriteResult, error) {
	if report.ID != d.layout.Output.ID || len(report.Data) != d.layout.Output.Size {
		return driver.WriteResult{Outcome: driver.OutcomeNotSubmitted}, &driver.Error{Op: "write", Kind: driver.KindInvalidReport}
	}
	buffer := make([]byte, len(report.Data)+1)
	buffer[0] = report.ID
	copy(buffer[1:], report.Data)
	n, err := unix.Write(d.fd, buffer)
	if err != nil {
		return driver.WriteResult{Outcome: driver.OutcomeUnknown}, nativeError("write", err)
	}
	if n != len(buffer) {
		return driver.WriteResult{Outcome: driver.OutcomeUnknown}, &driver.Error{Op: "write", Kind: driver.KindIO, Message: "short native write"}
	}
	return driver.WriteResult{Outcome: driver.OutcomeCompleted}, nil
}

// Close releases the fd after the core has joined native operations.
func (d *device) Close() error {
	if err := unix.Close(d.fd); err != nil {
		return nativeError("close", err)
	}
	return nil
}
