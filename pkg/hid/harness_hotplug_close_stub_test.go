//go:build hid_diagnostics && integration && (!darwin || !cgo)

package hid

// Portable checks lack the native proof for this macOS-only diagnostic.
func attachHotplugCloseProbe(Conn) (hotplugCloseProbe, error) { return nil, nil }
