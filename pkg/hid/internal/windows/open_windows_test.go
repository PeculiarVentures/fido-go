//go:build windows

package windows

import (
	"errors"
	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/driver"
	"golang.org/x/sys/windows"
	"testing"
)

func TestOpenIDOnly(t *testing.T) {
	const path = `\\?\hid#example`
	called := ""
	sys := openSystem{find: func(p string) (driver.Endpoint, error) {
		called = p
		return driver.Endpoint{ID: endpointID(p), Path: p}, nil
	}, open: func(string) (windows.Handle, error) { return 1, nil }, close: func(windows.Handle) error { return nil }, metadata: func(windows.Handle, *driver.Endpoint, bool) error { return nil }, layout: func(windows.Handle) (driver.Layout, error) {
		return driver.Layout{Input: driver.ReportSpec{Size: 64}, Output: driver.ReportSpec{Size: 64}}, nil
	}}
	got, err := openWithSystem(driver.Endpoint{ID: endpointID(path)}, sys)
	if err != nil || got == nil || called != path {
		t.Fatalf("ID-only open=%v error=%v path=%q", got, err, called)
	}

	called = ""
	_, err = openWithSystem(driver.Endpoint{ID: endpointID(path), Path: `other`}, sys)
	var native *driver.Error
	if !errors.As(err, &native) || native.Kind != driver.KindStaleEndpoint || called != "" {
		t.Fatalf("mismatched path error=%v find=%q", err, called)
	}
}
