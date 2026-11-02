# HID diagnostic harness

The diagnostic harness provides registered scenarios with structured evidence,
bounded cooperative execution, and explicit cleanup. It covers SIGURG, mask
faults, and connection lifecycle without adding diagnostic options to the public
HID API. Add new scenarios through the internal runner rather than creating
another one-off hardware script.

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

On macOS with cgo and connected USB FIDO test keys:

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
