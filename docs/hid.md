# Native HID API

`github.com/PeculiarVentures/fido-go/pkg/hid` provides HID inventory and native
Input/Output report I/O for macOS, Windows, and Linux. It is part of the existing
`fido-go` module and uses the normal SDK release tags. It has no dependency on
HIDAPI or `go-hid`.

The package is independent of CTAP, CTAPHID framing, PC/SC, and physical-token
identity. `pkg/transport/usb` owns channels, INIT/PING, packet framing, complete
exchanges, and the decision to retire a failed exchange. Applications own token
selection, identity validation, and recovery policy.

## Inventory

```go
backend := hid.New() // Lazy initialization; a zero hid.Native is also usable.
snapshot, err := backend.Enumerate(ctx, hid.EnumerateOptions{
    ResolveStrings: true,
})
if err != nil {
    return err
}
if !snapshot.Complete {
    // Keep the previous watcher snapshot. Missing entries do not prove removal.
    return fmt.Errorf("incomplete HID inventory: %v", snapshot.Warnings)
}
for _, endpoint := range snapshot.Endpoints {
    fmt.Println(endpoint.ID, endpoint.Path, endpoint.Product.Value)
}
```

Enumeration includes non-FIDO endpoints. `Field[T].Known` distinguishes missing
metadata from a known empty or zero value. Optional strings are resolved only
when requested. `Complete` describes an observation without known omissions;
it does not make enumeration atomic with hotplug.

Filters are a conjunction of exact constraints. A nil pointer leaves a field
unconstrained. An unknown field does not match a specified constraint; an
indeterminate membership makes the snapshot incomplete.

On Linux and macOS, collection usages come from the report descriptor. A
descriptor whose report layout is outside the supported I/O subset (for
example usage delimiters, long items, or reports outside an Application
collection) still resolves its top-level usages. Such collections are listed
with a warning, cannot be opened, and do not make the snapshot incomplete, so
an unrelated device cannot hide FIDO endpoints. For USB FIDO discovery:

```go
bus := hid.BusUSB
snapshot, err := backend.Enumerate(ctx, hid.EnumerateOptions{
    Filter: hid.Filter{
        Bus:   &bus,
        Usage: &hid.Usage{Page: 0xf1d0, ID: 0x01},
    },
    ResolveStrings: true,
})
```

`Endpoint.ID` is an opaque, case-sensitive address for an interface or
collection. Use it as the watcher snapshot key. Serial numbers can be shared
by several interfaces and must not be used as endpoint keys. `Path` is a native
locator for diagnostics and may be shared by collections. Neither identifier
proves the physical identity of a token after hotplug or address reuse.

## Opening and reports

Open the exact endpoint selected from an inventory snapshot:

```go
conn, err := backend.Open(ctx, selected)
if err != nil {
    return err
}
defer func() {
    cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
    defer cancel()
    _ = conn.Close(cleanup)
}()

layout := conn.Layout()
result, err := conn.Write(ctx, hid.Report{
    ID: layout.Output.ID,
    Data: packet,
})
if err != nil {
    // result.Outcome remains meaningful. Never replay a command automatically.
    return err
}
report, err := conn.Read(ctx, 0)
```

`Open` never falls back to another device with the same VID/PID. It validates
the opened endpoint against known expected metadata. A stale address or
descriptor is an error; successful open still requires application identity
validation where physical identity matters.

The first implementation accepts one unambiguous, fixed-size Input report and
one Output report per selected collection. Complex or shared layouts remain
visible in inventory but cannot be opened for I/O. The qualified use case is
USB FIDO. Feature reports and Bluetooth/BLE I/O are outside this API.

`Report.ID` is separate from `Report.Data`; layout sizes exclude the ID byte.
Bindings perform native prefix/padding handling from descriptor information.
Invalid IDs or lengths are rejected before submission. Short native I/O is
an error, never silently truncated or completed by replaying a write.

`Read` returns an independent buffer. `Write` copies data before native
submission and retains that copy until actual completion. Callers must not
change a write buffer during the call but may reuse it immediately on return,
including when the return is caused by cancellation.

## Delivery outcomes and errors

`WriteResult.Outcome` distinguishes `OutcomeNotSubmitted`,
`OutcomeCompleted`, and `OutcomeUnknown`. The zero value is unknown. Completed
means native report I/O succeeded; it does not confirm execution of a CTAP
command. After submission, cancellation or a generic I/O failure usually
leaves delivery unknown. Inspect the result even when an error is returned.

`errors.Is` preserves package categories and context errors. `errors.As` can
recover `*hid.Error` and `*hid.NativeError`, including the native error domain
and numeric code. Generic IOKit errors, including `0xe00002bc`, are I/O errors
without evidence of removal. The package does not expose a universal retryable
flag and does not automatically resend reports.

## Cancellation and ownership

One read and one write may run concurrently on a connection. A second call in
the same direction fails with `ErrBusy`. Complete CTAPHID exchanges are
serialized separately by the USB adapter.

`Read(ctx, 0)` waits until a report, context cancellation, or shutdown.
`Read(ctx, wait)` with a positive local wait returns `ErrTimeout` without
retiring the connection. This supports INIT/PING polling. A negative wait is
invalid. Local timeout leaves no abandoned native reader that could consume a
future report.

Context cancellation before admission leaves the connection usable.
Cancellation after admission retires it and rejects new I/O. `Close(ctx)` also
initiates retirement even when its context is already canceled. Successful
close means physical cleanup is complete. If its deadline expires, the
internal supervisor retains the handle, buffers, and callbacks until native
completion. Repeated close waits for the same cleanup. An active native call
is never interrupted by freeing its handle.

Retirement revokes new admission. An already accepted write keeps waiting for
its native result or its own caller context, even if another caller closes the
connection or the input pump fails. This preserves completion and native error
evidence. Supply a write deadline when caller waiting must be bounded;
`Close(ctx)` has its own independent cleanup deadline. The USB transport does this for every
CTAPHID report: a report write that does not complete within 5 seconds fails
the exchange with `ErrTimeout` and retires the session.

Admission and memory budgets are shared by all `Native` instances. Retiring or
quarantined work continues to count against those limits, including endpoint
exclusion. A new backend does not bypass them. Limits cover connections,
enumeration, queued reports, descriptor/report sizes, and owned native bytes.
Current bounds are 64 connections, one active enumeration (concurrent callers
wait for it under their own context), and 64 MiB reserved for
owned buffers (768 KiB per connection and 16 MiB per enumeration). Inventory is
bounded to 128 native devices and 1,024 collection endpoints; descriptors are
limited to 64 KiB and reports to 4,096 data bytes. These are resource ceilings,
not a promise that every layout below the ceilings is supported.
An unresponsive driver can exhaust admission and require process restart, but
cannot cause an unbounded stream of replacement workers. Contexts bound caller
waiting; they cannot promise hard real-time interruption of arbitrary kernel
or driver code.

The SDK keeps `transport.Session.Close()` compatible and adds the optional
`transport.ContextCloser` interface for a caller-provided cleanup deadline.
The built-in client forwards context-aware closing. Native USB `Close()` uses
a bounded default cleanup wait. After an ambiguous application exchange the
session is retired; only the documented safe INIT/PING handshake may retry.

## Platforms and migration

macOS uses IOKit/CoreFoundation through cgo. A dedicated native writer thread
protects SetReport with save/block/restore of its own SIGURG mask; the Go
scheduler's process-wide signal policy is unchanged. Input callbacks and
their buffers are native-owned. The first version uses protected synchronous
SetReport; an asynchronous implementation requires separate qualification.

Windows uses SetupAPI/HID and overlapped Win32 I/O. Cancellation waits for
completion before releasing OVERLAPPED state or buffers. Filtered Windows
inventory reads HID interface properties before opening collections. Known
nonmatching collections are excluded without opening them; unknown membership
leaves the snapshot incomplete and does not cause a collection to be opened.
Linux uses sysfs,
hidraw, and poll without libudev; service accounts need appropriate udev/ACL
permissions. Unsupported systems and macOS without cgo return `ErrUnsupported`.

GoodKey must replace its direct `go-hid` watcher import and adapt metadata,
snapshot completeness, and endpoint keys. Updating the SDK dependency alone
does not migrate the watcher or add application identity recovery.

A later move to `cardkit-go/transport/hid` can preserve the old import path
using type aliases, forwarded constructors, and shared sentinel errors. There
must be only one native runtime. The new HID module must not depend on
`fido-go` or an aggregating cardkit SDK.

Protocol behavior follows [CTAP 2.2 USB HID discovery](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#usb-discovery),
INIT, and PING (sections 11.2.8.2, 11.2.9.1.3, and 11.2.9.1.4).

## Hardware validation

For synchronized SIGURG/mask fault injection, multi-report PING, concurrent
exchange, cancellation/Close, and operator-assisted unplug/replug or sleep/wake
checks, see
[the extensible diagnostic harness](hid-diagnostics.md). Its hooks are compiled
only with the `hid_diagnostics` tag.

The harness reports HID/native and production USB session checks as separate
layers. Its shared runner validates required evidence after cleanup and before
writing the final verdict to JSON. Hardware checks of the production USB API
run through `TestUSBDiagnosticsHardware` in `pkg/transport/usb`.

Default unit tests use synthetic devices. A separate opt-in test performs only
INIT/PING/GetInfo against connected USB FIDO endpoints:

```sh
FIDO_HID_TEST=1 go test -tags=integration ./pkg/transport/usb -run TestNativeHIDHardware -v
```

It does not reset the authenticator, attempt a PIN, or create credentials.
Run hardware tests with the service account and device permissions used by the
application. Windows/Linux hardware, macOS x86_64 and numbered reports,
SIGURG coverage on other hardware/toolchains, removal/callback teardown fault
injection, sleep/wake on other platforms and configurations, and native
allocation/sanitizer checks require separate
qualification before production release. Compilation and synthetic CI tests
do not establish those properties.
