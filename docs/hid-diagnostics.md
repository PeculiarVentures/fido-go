# HID diagnostic harness

The diagnostic harness provides registered scenarios with structured evidence,
bounded cooperative execution, and explicit cleanup. It covers SIGURG, mask
faults, connection lifecycle, and read-only physical-device exchanges without
adding diagnostic options to the public HID API. Add new scenarios through the
internal runner rather than creating another one-off hardware script.

The harness stays in the main Go module with these ownership boundaries:

- `internal/diagnostics` owns cooperative execution, cleanup, evidence validation,
  selection, and JSON output. It has no HID or CTAPHID dependencies.
- `pkg/hid` keeps scenarios that inspect private connection state or native
  probes. Its test-only catalog in `harness_catalog_test.go` owns each ID, layer,
  execution mode, prerequisites, timeout, and evidence validator.
- `pkg/transport/usb` checks production USB sessions through public
  `HIDBackend` and `HIDSession.ExchangeHID` APIs. Native hooks remain beside the
  Darwin backend; the optional debugger driver lives in `tools/hid_diagnostics`.
- `internal/diagnostics/power` shares the diagnostics-only system sleep/wake
  observer between HID and USB suites. The runner itself has no native bindings.
- `pkg/client` has a separate [client/CTAP2 scenario catalog](client-diagnostics.md)
  for credential lifecycle, persistence, PIN operations, and explicitly confirmed
  reset through the public production SDK. Its modifying opt-ins are independent
  of the read-only HID and USB suites.

Platform files supply callbacks by ID. They are joined to the catalog in one
pass before execution; unknown, duplicate, and missing available callbacks are
rejected before I/O. Pure validators and report output are tested with prepared
records, while the main suite checks actual native evidence collection.

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
go test -count=1 -tags=hid_diagnostics ./internal/diagnostics/... ./pkg/hid/... ./pkg/transport/usb/...
go test -race -count=1 -tags='hid_diagnostics integration' ./internal/diagnostics/... ./pkg/hid/... ./pkg/transport/usb/...
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

Every build retains the same catalog IDs. Selecting a Darwin scenario on
Linux, Windows, or a build without cgo produces `SKIP` with the missing
prerequisite, rather than an unknown-ID error. Hardware, strict, and interactive
modes have separate opt-ins; an unrequested mode also produces `SKIP`.

CI runs deterministic diagnostics and compiles the complete integration set on
Linux, macOS, and Windows, including configurations without cgo. Integration
compilation uses `-run='^$'` and does not access hardware. Hardware entrypoints
also remain skipped without their environment opt-ins during diagnostic tests.

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

The `hardware.*` scenarios qualify the HID report/connection layer. Their small
INIT/PING driver uses the production wire codec to support exact injection and
response barriers; it does not exercise production USB session orchestration.
Use the USB suite below to qualify that layer. Each JSON record names its
checked layer (`hid`, `hid-native`, or `usb-session`).

| Scenario | Procedure and required evidence |
| --- | --- |
| `hardware.setup-mask-failure` | On each real Darwin endpoint, initialize a channel, then inject a mask setup error for one PING write. Require `OutcomeNotSubmitted`, zero native SetReport calls, the intact prior mask, retired admission and joined cleanup. A fresh writer must complete INIT/PING. |
| `hardware.restore-mask-failure` | Inject a mask restore error after one real PING submission. Preserve the completed write outcome and restore errno, retain the protected mask until the damaged writer exits, reject reuse, and join cleanup. A fresh writer must complete INIT/PING. |
| `hardware.multiframe-ping` | On every selected key, send fresh PING payloads of 0, 57, 58, 128, and 1,024 bytes using the production codec. Verify exact echoes and report counts across the 57-byte initial / 59-byte continuation boundaries of a 64-byte layout. |
| `hardware.parallel-exchange` | Open at least two keys, exchange distinct fresh payloads concurrently, and poll complete inventories while workers are active. Verify response isolation, worker completion, and cleanup. This records concurrent exchanges; it does not infer simultaneous kernel execution. |
| `hardware.cancel-close` | Cancel an admitted read and close a connection with a pending read. On Darwin, also hold an admitted real-device write at the protected boundary, cancel it, verify bounded Close while native ownership is retained, then release and join cleanup. Reject old-connection reuse and verify a fresh INIT/PING. The write barrier is before IOKit entry, so this does not prove cancellation inside an executing IOKit call. |
| `hardware.unplug-replug` | Prompt for removal and same-port reconnection of each selected key. Observe complete inventory absence/reappearance, bounded failure and cleanup of the old connection, failed exact Open while absent, a usable surviving neighbor, and fresh discovery/INIT/PING after reconnection. Requires the separate interactive opt-in below. |
| `hardware.sleep-wake-idle` | Keep initialized, warmed-up sessions idle across an observed system sleep/wake cycle. Check each old session after wake, record any explicit failure, complete cleanup, and verify fresh discovery/INIT/PING for each selected key. Requires the separate sleep opt-in. |
| `hardware.sleep-wake-exchange` | Submit one fresh PING per selected key and hold response consumption across an observed system sleep/wake cycle. Verify each original echo or record its explicit failure, join all callers, complete cleanup, and verify fresh sessions. This proves outstanding logical exchanges, without proving native/kernel I/O in flight at sleep. |
| `hardware.identical-keys` | Use operator labels A/B for two same-descriptor keys. Check each removal while the other connection remains usable, exact stale-address rejection, fresh recovery, swapped-port substitution, and refusal to choose an unlabelled ambiguous candidate. Requires its own interactive opt-in. |

For example, run fragmentation, concurrency, and cancellation without physical
disconnection:

```sh
FIDO_HID_DIAGNOSTICS=1 \
FIDO_HID_DIAGNOSTICS_SCENARIOS=hardware.multiframe-ping,hardware.parallel-exchange,hardware.cancel-close \
FIDO_HID_DIAGNOSTICS_REPORT=/absolute/path/hid-exchanges.json \
go test -count=1 -tags='hid_diagnostics integration' \
  ./pkg/hid -run '^TestHIDDiagnosticsHardware$' -v -timeout=3m
```

Run the real-endpoint mask fault checks separately on macOS with cgo:

```sh
FIDO_HID_DIAGNOSTICS=1 \
FIDO_HID_DIAGNOSTICS_SCENARIOS=hardware.setup-mask-failure,hardware.restore-mask-failure \
FIDO_HID_DIAGNOSTICS_REPORT=/absolute/path/hid-mask-faults.json \
CGO_ENABLED=1 go test -count=1 -tags='hid_diagnostics integration' \
  ./pkg/hid -run '^TestHIDDiagnosticsHardware$' -v -timeout=3m
```

These scenarios inject mask-operation failures on the production native writer;
they do not substitute the native device I/O result. Setup failure must never
reach SetReport. Restore failure proves native delivery completion, not receipt
of the original PING echo: retirement may discard that input. Recovery uses a
new connection and fresh INIT/PING, without replaying the failed exchange.
Reports distinguish the damaged and fresh writer generations, retain native
error codes, and require real-device and completed-cleanup evidence per key.
Other platforms retain these scenario IDs with an explicit unavailable result.

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
observations; it does not establish durable physical-token identity. Use the
dedicated identical-key and sleep/wake scenarios for those checks. Removal
during Open/Close and broader USB topologies remain separate qualification
cases.

The Darwin hotplug check distinguishes reclaimed resources from a successful
native Close call. A removed device was observed returning IOKit `0xe00002c2`
from Close after teardown. The harness retains that code and the SDK's Close
error. It can qualify cleanup for this specific diagnostic only after complete
inventory absence, an independent removal error, and matching real native
writer exit/join, device release, and completed core cleanup. It records that
native Close did not succeed; the code alone never proves removal. Other Close
errors and missing cleanup evidence remain failures.

## Operator-assisted sleep/wake

Sleep checks currently require macOS with cgo and a diagnostic native power
observer. Linux, Windows, and builds without that observer retain the scenario
IDs with an explicit missing prerequisite. Each scenario checks all selected
keys together, so the two scenarios require two system sleep/wake cycles.

```sh
FIDO_HID_DIAGNOSTICS=1 \
FIDO_HID_DIAGNOSTICS_SLEEP=1 \
FIDO_HID_DIAGNOSTICS_SCENARIOS=hardware.sleep-wake-idle,hardware.sleep-wake-exchange \
FIDO_HID_DIAGNOSTICS_REPORT=/absolute/path/hid-sleep-wake.json \
CGO_ENABLED=1 go test -count=1 -tags='hid_diagnostics integration' \
  ./pkg/hid -run '^TestHIDDiagnosticsHardware$' -v -timeout=30m
```

Keep both keys connected. Wait for `HID_OPERATOR phase=sleep-idle keys=...` or
`phase=sleep-exchange`. Choose **Sleep** from the Apple menu, leave the Mac
asleep for about ten seconds, then wake and unlock it. Wait for the next prompt
before repeating. Display sleep or locking the screen alone does not qualify.
If the test exits, earlier prompts no longer apply.

The native observer registers with `IORegisterForSystemPower` before prompting,
acknowledges sleep requests without vetoing them, and requires an ordered
`SystemWillSleep` / `SystemHasPoweredOn` pair for the current arm generation.
Elapsed time alone cannot qualify a cycle. Stale, canceled, out-of-order, and
extra cycles cannot qualify. Observer registration and native cleanup are
included in the evidence. The observer follows [Apple's sleep/wake notification
and teardown procedure](https://developer.apple.com/library/archive/qa/qa1340/_index.html).

The exchange scenario holds complete submitted PINGs at a response-consumption
barrier until wake; responses may already have been buffered before sleep. It
does not establish that a native syscall or kernel transfer remained in flight.
Each request is sent once. A fresh session after wake uses a new request; it
does not replay a failed application exchange. Recovery selects a unique
observed descriptor and does not prove durable physical-token identity.

Sleep and unplug are independent opt-ins: `FIDO_HID_DIAGNOSTICS_SLEEP` never
enables unplug prompts, and `FIDO_HID_DIAGNOSTICS_UNPLUG` never enables sleep
prompts. The harness observes power events; it never forces sleep itself.

## Two identical keys

Use exactly two USB FIDO keys with matching known model/usage/interface
descriptors and distinct endpoint addresses. Mark them physically **A** and **B**
and remember their original ports. Both keys initialize and warm up before the
first action. The first removal establishes the operator's A/B mapping from a
complete inventory observation; neither serial strings nor VID/PID alone assign
the labels.

```sh
FIDO_HID_DIAGNOSTICS=1 \
FIDO_HID_DIAGNOSTICS_IDENTICAL=1 \
FIDO_HID_DIAGNOSTICS_SCENARIOS=hardware.identical-keys \
FIDO_HID_DIAGNOSTICS_REPORT=/absolute/path/hid-identical-keys.json \
go test -count=1 -tags='hid_diagnostics integration' \
  ./pkg/hid -run '^TestHIDDiagnosticsHardware$' -v -timeout=60m
```

Wait for each `HID_OPERATOR phase=identical-... keys=2` event. The sequence is:

1. Remove A, leaving B connected.
2. Reconnect A to its original port.
3. Remove B, leaving A connected.
4. Reconnect B to its original port.
5. Remove both keys.
6. Connect only B to A's former port, keeping A disconnected.
7. Connect A to B's former port.

Each transition has a bounded observation window. The harness requires complete
inventories, unchanged surviving addresses/metadata, and successful PING through
the same surviving connection. Removed sessions must report removal and finish
cleanup; an address confirmed absent must reject exact Open without selecting
the identical neighbor. Incomplete inventory is never absence evidence.

Recovery opens only the explicitly observed current endpoint after the operator
action. An unlabelled inventory with two matching candidates must refuse an
automatic selection and perform no automatic Open. Endpoint IDs are connection
addresses, not durable physical-token identities. Address reuse is reported
conservatively; this diagnostic does not establish cryptographic card identity.
Port swaps follow the operator's instructions and observations, rather than
claiming independently verified USB port topology.

The identical-key opt-in does not enable unplug/replug or sleep scenarios.
Keep following only the current process's prompts; they expire when it exits.
This check uses read-only traffic and does not reset keys or change credentials.

## Production USB session scenarios

The separate USB suite uses production discovery, channel initialization, and
complete-message exchange. It never implements its own CTAPHID exchange loop:

- `usb.multiframe-ping` verifies exact fresh echoes for payload sizes 0, 57, 58,
  128, and 1,024 bytes through `HIDSession.ExchangeHID`.
- `usb.parallel-exchange` opens at least two independent sessions, warms them up,
  starts concurrent callers with distinct fresh payloads, checks complete
  inventory, verifies isolated responses, and joins all callers before cleanup.
  It does not claim that native calls overlapped; the HID response-barrier
  scenario supplies that separate evidence.
- `usb.sleep-wake-idle` holds warmed production sessions idle across actual
  system sleep/wake notifications, records each old session's post-wake result,
  and verifies fresh production discovery/Open/INIT/PING and bounded Close.
- `usb.sleep-wake-exchange` invokes a fresh 1,024-byte production ExchangeHID
  on each key. A test-only HID Read decorator holds response consumption after
  all 18 writes have completed, until actual system wake. Production USB code
  still owns channel state, serialization, framing, and reassembly.

```sh
FIDO_USB_DIAGNOSTICS=1 \
FIDO_USB_DIAGNOSTICS_REPORT=/absolute/path/usb-diagnostics.json \
go test -count=1 -tags='hid_diagnostics integration' \
  ./pkg/transport/usb -run '^TestUSBDiagnosticsHardware$' -v -timeout=3m
```

Optional `FIDO_USB_DIAGNOSTICS_ENDPOINTS` and
`FIDO_USB_DIAGNOSTICS_SCENARIOS` accept comma-separated exact endpoint IDs and
scenario IDs respectively. Unknown or duplicate selections are rejected before
opening devices. Endpoint IDs and payloads are excluded from reports. Without
hardware, the diagnostic tests exercise these same scenarios against production
USB sessions backed by a synthetic HID report device, including corrupt echoes.

For production USB sleep/wake on macOS with cgo:

```sh
FIDO_USB_DIAGNOSTICS=1 \
FIDO_USB_DIAGNOSTICS_SLEEP=1 \
FIDO_USB_DIAGNOSTICS_SCENARIOS=usb.sleep-wake-idle,usb.sleep-wake-exchange \
FIDO_USB_DIAGNOSTICS_REPORT=/absolute/path/usb-sleep-wake.json \
CGO_ENABLED=1 go test -count=1 -tags='hid_diagnostics integration' \
  ./pkg/transport/usb -run '^TestUSBDiagnosticsHardware$' -v -timeout=30m
```

Keep both keys connected. Wait for `USB_OPERATOR phase=usb-sleep-idle keys=...`
or `phase=usb-sleep-exchange`, choose **Sleep** from the Apple menu, wait about
ten seconds, then wake and unlock the Mac. Each scenario uses one cycle for
both keys. The observer must confirm the ordered current-generation sleep/wake
pair and complete native teardown; a prompt or elapsed delay is insufficient.

Old-session errors retain their categories, native codes, and ExchangeError
stage, delivery outcome, submitted packet count, and ambiguity. An error does
not authorize replay. Cleanup uses production `CloseContext`; unqualified Close
errors remain failures even if a later wait succeeds. Fresh recovery first
reserves unchanged exact endpoint IDs, so two identical keys remain selectable.
Changed addresses require a unique unclaimed matching candidate; ambiguous
replacement candidates cannot be selected automatically. No physical identity
is inferred from endpoint addresses or model metadata.

Responses may already be buffered before sleep. The response barrier proves a
production transaction is outstanding, without proving a native syscall or
kernel transfer is in flight. The USB sleep flag is independent of HID sleep,
unplug and identical-key opt-ins. Unsupported power-observer builds retain the
scenario IDs with SKIP results. The harness never initiates sleep itself.

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
  -o 'command script import /absolute/path/fido-go/tools/hid_diagnostics/lldb_sigurg.py' \
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
checked layers, opt-in modes, requirements, durations, cleanup outcome, counters, Boolean observations, and
selected native error domains/codes. They do not collect environment variables,
full device serials, or report payloads.

After the callback returns, the runner completes cleanup, snapshots evidence,
and invokes the scenario's validator before finalizing `PASS`. Missing required
facts or inconsistent counters produce `FAIL` in the saved JSON itself.
Entrypoints consume these finalized verdicts; they do not apply separate evidence
rules after writing the report. The additive `layer` and `mode` fields retain
schema version 1; an omitted mode denotes deterministic execution.

- `PASS`: the scenario obtained and verified all required evidence.
- `FAIL`: an assertion, native operation, deadline, or cleanup failed.
- `SKIP`: a prerequisite was unavailable before attempting the scenario.
- `INCONCLUSIVE`: the attempt did not obtain evidence required to qualify it.

An aggregate test process exit code does not convert skipped or inconclusive
scenarios into qualified checks. Qualification records must retain the JSON
report and distinguish synthetic, pending-critical-section, and confirmed
IOKit-entry evidence.

## Adding a scenario

Add a definition to the owning suite's explicit catalog with a unique ID,
checked layer, execution mode, requirements, timeout, and evidence validator.
Bind a cooperative callback in the appropriate platform implementation. Keep
unavailable IDs in the catalog; do not add platform-specific expected-ID lists
or aggregate stubs. Validators are bounded, read-only functions without I/O;
test their rejection of incomplete evidence. No `init()` registration is needed.

Register cleanup before acquiring a resource;
callbacks run in reverse order with an independent cleanup budget even after
parent cancellation. Record facts from observations and do not infer native
completion or signal overlap from elapsed time.

Keep native hooks platform-specific and diagnostics-only. Physical-token
identity, PIN/credential operations, and application recovery policy remain in
their existing client/application layers. New hardware cases require explicit
opt-in and an accurate list of prerequisite devices and permissions.
