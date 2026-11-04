//go:build hid_diagnostics && integration && darwin && cgo

package hid

import (
	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/darwin"
	"github.com/PeculiarVentures/fido-go/pkg/hid/internal/driver"
)

type darwinHotplugCloseProbe struct {
	probe      *darwin.Probe
	generation uint64
}

func attachHotplugCloseProbe(conn Conn) (hotplugCloseProbe, error) {
	var probe *darwin.Probe
	err := withDiagnosticDevice(conn, func(device driver.Device) error {
		var err error
		probe, err = darwin.Attach(device)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &darwinHotplugCloseProbe{probe: probe, generation: probe.Snapshot().Generation}, nil
}

func (probe *darwinHotplugCloseProbe) proof() hotplugCloseProof {
	snapshot := probe.probe.Snapshot()
	return hotplugCloseProof{
		RealProbe:    !snapshot.Synthetic,
		SameProbe:    probe.generation != 0 && snapshot.Generation == probe.generation,
		WriterExited: snapshot.WriterExited, WriterJoined: snapshot.WriterJoined, DeviceClosed: snapshot.DeviceClosed,
	}
}

func (probe *darwinHotplugCloseProbe) close() error { return probe.probe.Close() }
