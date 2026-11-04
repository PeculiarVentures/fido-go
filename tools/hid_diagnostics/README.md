# HID debugger tooling

`lldb_sigurg.py` launches the diagnostic Go test binary and injects SIGURG at
confirmed `IOHIDDeviceSetReport` entry on an armed writer. It requires macOS,
cgo, LLDB, and explicit read-only hardware opt-in.

See [HID diagnostics](../../docs/hid-diagnostics.md#strict-native-entry-injection)
for compilation, invocation, evidence requirements, and report formats. The
shared Go runner lives in `internal/diagnostics`; native hooks remain in
`pkg/hid/internal/darwin`.
