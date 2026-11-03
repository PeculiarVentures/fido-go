# HID diagnostic harness

The diagnostic harness provides registered scenarios with structured evidence,
bounded cooperative execution, and explicit cleanup. It covers SIGURG, mask
faults, connection lifecycle, and read-only physical-device exchanges without
adding diagnostic options to the public HID API. Add new scenarios through the
internal runner rather than creating another one-off hardware script.

## Build boundaries

`hid_diagnostics` enables test helpers and native hooks. An ordinary build has
no injection controls. The macOS diagnostic backend exercises the production
`protected_write` and writer loop; synthetic scenarios substitute only native
I/O and the selected mask-operation result. Per-probe state is native-owned and
does not retain Go pointers.

Hardware diagnostics also require the `integration` tag and
`FIDO_HID_DIAGNOSTICS=1`. They send only INIT/PING and never reset a key, attempt
a PIN, or change credentials. Use test devices and the account/device access
configuration that the application will use.

## Deterministic scenarios

```sh
go test -count=1 -tags=hid_diagnostics ./pkg/hid/...
go test -race -count=1 -tags=hid_diagnostics ./pkg/hid/...
```

The suite includes:

- Exact mask restoration when SIGURG was initially blocked or unblocked,
  including another signal that must remain blocked.
- A synchronized injector using `pthread_kill` on the live native writer.
  Evidence records the writer generation and writer-local pending/masked state.
- Setup failure before submission: zero native SetReport calls and
  `OutcomeNotSubmitted`.
- Restore failure after submission: preserve native delivery evidence and mask
  errors separately, exit/join the affected writer, and reject further work on
  that connection. A fresh connection must remain usable.
- Close/cancellation with blocked native work, endpoint admission during
  retirement, repeated close, deferred cleanup, and isolation of late input
  from a reopened connection.

These checks use barriers and condition variables instead of timing guesses.
The native mask scenarios require macOS with cgo. Generic runner and lifecycle
checks also run on other supported platforms. Unavailable prerequisites produce
an explicit result rather than a successful native check.

## Hardware scenarios and reports

With connected USB FIDO test keys (macOS requires cgo):

```sh
FIDO_HID_DIAGNOSTICS=1 \
FIDO_HID_DIAGNOSTICS_REPORT=/absolute/path/hid-diagnostics.json \
CGO_ENABLED=1 go test -count=1 -tags='hid_diagnostics integration' \
  ./pkg/hid -run '^TestHIDDiagnosticsHardware$' -v -timeout=3m
```

By default all discovered qualified endpoints are checked. To select endpoints,
set `FIDO_HID_DIAGNOSTICS_ENDPOINTS` to a comma-separated list of exact opaque
endpoint IDs. Selectors and serial numbers are not included in the report.

The harness initializes each channel before arming a fault or signal injection,
then sends a PING with a fresh payload and verifies the exact echo. The
pending-critical-section scenario proves SIGURG is pending before the real
SetReport and that masking protects the native call. It does not claim that
the signal was first generated inside the IOKit function.

Select individual scenarios with `FIDO_HID_DIAGNOSTICS_SCENARIOS`, a
comma-separated list of scenario IDs. Unknown IDs are rejected before device
operations. A selected result qualifies only when its status is `PASS` and its
cleanup is complete. The portable exchange scenarios can run on Linux and
Windows too; running them on macOS does not qualify another platform.

| Scenario | Procedure and required evidence |
| --- | --- |
| `hardware.multiframe-ping` | On every selected key, send fresh PING payloads of 0, 57, 58, 128, and 1,024 bytes using the production codec. Verify exact echoes and report counts across the 57-byte initial / 59-byte continuation boundaries of a 64-byte layout. |
| `hardware.parallel-exchange` | Open at least two keys, exchange distinct fresh payloads concurrently, and poll complete inventories while workers are active. Verify response isolation, worker completion, and cleanup. This records concurrent exchanges; it does not infer simultaneous kernel execution. |
| `hardware.cancel-close` | Cancel an admitted read and close a connection with a pending read. On Darwin, also hold an admitted real-device write at the protected boundary, cancel it, verify bounded Close while native ownership is retained, then release and join cleanup. Reject old-connection reuse and verify a fresh INIT/PING. The write barrier is before IOKit entry, so this does not prove cancellation inside an executing IOKit call. |
| `hardware.unplug-replug` | Prompt for removal and same-port reconnection of each selected key. Observe complete inventory absence/reappearance, bounded failure and cleanup of the old connection, failed exact Open while absent, a usable surviving neighbor, and fresh discovery/INIT/PING after reconnection. Requires the separate interactive opt-in below. |

For example, run fragmentation, concurrency, and cancellation without physical
disconnection:

```sh
FIDO_HID_DIAGNOSTICS=1 \
FIDO_HID_DIAGNOSTICS_SCENARIOS=hardware.multiframe-ping,hardware.parallel-exchange,hardware.cancel-close \
FIDO_HID_DIAGNOSTICS_REPORT=/absolute/path/hid-exchanges.json \
go test -count=1 -tags='hid_diagnostics integration' \
  ./pkg/hid -run '^TestHIDDiagnosticsHardware$' -v -timeout=3m
```

For the operator-assisted check, keep the other key connected and reconnect the
requested key through the same port. Do not unplug anything until the process
prints `HID_OPERATOR phase=unplug ...`. Wait for `phase=replug` before
reconnecting. Each event identifies only the key ordinal and VID:PID. A prompt
alone is not evidence: the harness waits up to five minutes per inventory
transition, with a 25-minute scenario deadline. If the process exits or times
out, its earlier prompts no longer apply.

```sh
FIDO_HID_DIAGNOSTICS=1 \
FIDO_HID_DIAGNOSTICS_UNPLUG=1 \
FIDO_HID_DIAGNOSTICS_SCENARIOS=hardware.unplug-replug \
FIDO_HID_DIAGNOSTICS_REPORT=/absolute/path/hid-hotplug.json \
go test -count=1 -tags='hid_diagnostics integration' \
  ./pkg/hid -run '^TestHIDDiagnosticsHardware$' -v -timeout=30m
```

Ambiguous replacements or changes to a neighboring key cannot qualify as a
successful reconnect. This diagnostic uses operator selection and inventory
observations; it does not establish durable physical-token identity. Different
ports, identical keys, removal during Open/Close, and sleep/wake remain separate
qualification cases.

The Darwin hotplug check distinguishes reclaimed resources from a successful
native Close call. A removed device was observed returning IOKit `0xe00002c2`
from Close after teardown. The harness retains that code and the SDK's Close
error. It can qualify cleanup for this specific diagnostic only after complete
inventory absence, an independent removal error, and matching real native
writer exit/join, device release, and completed core cleanup. It records that
native Close did not succeed; the code alone never proves removal. Other Close
errors and missing cleanup evidence remain failures.

## Strict native-entry injection

An injector observing a before-call flag cannot prove entry into the actual
IOHIDDeviceSetReport function. Strict mode requires an LLDB breakpoint at that
function and a test-only helper on the selected live writer. The helper verifies
armed state and generation, requests SIGURG on that thread, and records native
entry evidence. The debugger must pass SIGURG through without stopping or
replacing Go's handler. Go preemption remains enabled.

Strict execution uses the versioned LLDB driver supplied with the harness.
The driver launches a compiled diagnostic test binary; normal deterministic CI
does not depend on a debugger or attached hardware. A missing matching entry or
unavailable debugger cannot qualify the strict scenario. No system security
protections need to be disabled for the harness; report a debugger permission
failure explicitly.

From the repository root, compile and run on macOS:

```sh
CGO_ENABLED=1 go test -c -tags='hid_diagnostics integration' \
  -o /absolute/path/hid-diagnostics.test ./pkg/hid

xcrun lldb --batch \
  -o 'command script import /absolute/path/fido-go/pkg/hid/internal/diagnostics/tooling/lldb_sigurg.py' \
  -o 'hid-diagnostics-run /absolute/path/hid-diagnostics.test /absolute/path/hid-diagnostics.json --timeout=90'
```

The command writes the Go report and a companion
`hid-diagnostics.json.lldb.json` containing actual API breakpoint hits, armed
writer hits, successful injections, debugger errors, and target exit status.
An existing Go report is removed before launch, so an old success cannot be
reused. `--timeout` configures Go's test timeout; it is not an independent
wall-clock watchdog for a stalled debugger.

Strict success requires every selected key to have a matching writer, signal
target and native-entry generation, SIGURG blocked and pending at that entry,
one completed native PING, exact echo, restored mask, and joined writer. Signals
pending before the call and signals injected at actual API entry remain
separate scenario records.

## Result contract

Reports contain a schema version, OS/architecture/Go version, scenario IDs,
requirements, durations, cleanup outcome, counters, Boolean observations, and
selected native error domains/codes. They do not collect environment variables,
full device serials, or report payloads.

- `PASS`: the scenario obtained and verified all required evidence.
- `FAIL`: an assertion, native operation, deadline, or cleanup failed.
- `SKIP`: a prerequisite was unavailable before attempting the scenario.
- `INCONCLUSIVE`: the attempt did not obtain evidence required to qualify it.

An aggregate test process exit code does not convert skipped or inconclusive
scenarios into qualified checks. Qualification records must retain the JSON
report and distinguish synthetic, pending-critical-section, and confirmed
IOKit-entry evidence.

## Adding a scenario

Define an internal `diagnostics.Scenario` with a unique ID, requirements, timeout,
and a cooperative callback. Register cleanup before acquiring a resource;
callbacks run in reverse order with an independent cleanup budget even after
parent cancellation. Record facts from observations and do not infer native
completion or signal overlap from elapsed time.

Keep native hooks platform-specific and diagnostics-only. Physical-token
identity, PIN/credential operations, and application recovery policy remain in
their existing client/application layers. New hardware cases require explicit
opt-in and an accurate list of prerequisite devices and permissions.
