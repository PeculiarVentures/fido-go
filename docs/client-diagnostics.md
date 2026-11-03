# Client and CTAP2 diagnostic harness

The client harness checks observable authenticator behavior through the public
production SDK. It shares `internal/diagnostics` with the [HID and USB
harnesses](hid-diagnostics.md), while keeping PIN and credential semantics in
test-only `pkg/client` scenarios. Ordinary builds contain no client diagnostic
entrypoint. Hardware execution requires both `hid_diagnostics` and `integration`.

Each invocation selects one exact USB endpoint. There is no first-device,
VID/PID, model, or serial-number fallback for a modifying operation. After
physical reconnection, a changed address requires explicit enrollment of the
replacement endpoint. An address or matching model does not prove physical
identity.

## Scenarios

| Scenario | Preconditions and acceptance goal |
| --- | --- |
| `client.info-pin-status` | Read CTAP2 capabilities and PIN state/retries without attempting a PIN. |
| `client.credential-lifecycle` | With a known PIN and credential-management support, create a unique test credential, enumerate it, obtain an assertion, verify its signature, delete it, and confirm absence. |
| `client.credential-persistence` | Create and verify an owned credential, close the session, prompt for physical removal/reconnection, then reopen the explicitly selected endpoint and verify the same credential before deleting it. |
| `client.pin-set` | Require a fresh session reporting no configured PIN; set the supplied PIN, reopen, and prove authorization succeeds. This leaves a configured PIN. |
| `client.pin-change` | Prove the supplied original PIN works, change to a supplied temporary PIN, prove authorization with it, restore the original PIN, and prove authorization again. Restoration is checked and may fail if prohibited by device policy. |
| `client.reset` | Require a separate destructive opt-in and current-target confirmation. Create an owned test credential, prompt for the required power cycle and touch, reset once, then reopen and check PIN state and rejection of the old credential. |

Unsupported capabilities produce `SKIP`, not a successful check. A timeout or
transport failure after submitting a mutation does not prove that the mutation
failed. Such a result preserves uncertainty and is not retried automatically.
No scenario intentionally guesses a PIN or exhausts PIN retry counters.

## Selecting and running checks

The hardware entrypoint is `TestClientDiagnosticsHardware` in `pkg/client`.
Set `FIDO_CLIENT_DIAGNOSTICS=1`, the mandatory
`FIDO_CLIENT_DIAGNOSTICS_ENDPOINT` exact selector, and a comma-separated
`FIDO_CLIENT_DIAGNOSTICS_SCENARIOS` list. An unknown scenario or an invalid
selector is rejected before opening a device. With no scenario selection, only
the information/PIN-status check runs, even if modifying opt-ins remain set in
the environment. Every modifying scenario needs its explicit scenario ID as
well as its opt-in.

```sh
FIDO_CLIENT_DIAGNOSTICS=1 \
FIDO_CLIENT_DIAGNOSTICS_ENDPOINT="$selected_endpoint" \
FIDO_CLIENT_DIAGNOSTICS_SCENARIOS=client.info-pin-status \
FIDO_CLIENT_DIAGNOSTICS_REPORT=/absolute/path/client-info.json \
go test -count=1 -tags='hid_diagnostics integration' ./pkg/client \
  -run '^TestClientDiagnosticsHardware$' -v -timeout=3m
```

Additional environment settings have the `FIDO_CLIENT_DIAGNOSTICS_` prefix:

| Suffix | Purpose |
| --- | --- |
| `CREDENTIALS=1` | Permit creation and deletion of invocation-owned test credentials. |
| `PERSISTENCE=1` | Permit the prompted physical-reconnection scenario. |
| `PIN_SET=1` | Permit explicit initial PIN configuration. |
| `PIN_CHANGE=1` | Permit the temporary PIN-change/restoration scenario. |
| `RESET=1` | Permit the separately confirmed destructive reset scenario. |
| `PIN_FILE` | Absolute path to the protected current-PIN file. |
| `NEW_PIN_FILE` | Absolute path to the protected PIN used by PIN setup. |
| `TEMP_PIN_FILE` | Absolute path to the protected temporary PIN. |
| `ACK_FILE` | Protected operator-response file for interactive phases. |
| `REPORT` | Absolute destination for the structured JSON report. |

Persistence and reset also require `CREDENTIALS=1` because both create an owned
test credential. PIN setup and change require credential-management support to
prove authorization with the resulting PIN without intentionally entering a
wrong PIN.

PIN files contain only the PIN bytes, not JSON. Use regular files with owner-only
permissions and keep their containing directory private. The harness reads bounded
values into wipeable `client.Secret` buffers. Do not put PIN values in command
arguments, traces, or diagnostic reports. Retain a temporary-PIN file if
restoration fails; it may describe the card's current known PIN.

Secure file input is currently implemented on macOS and Linux. Windows builds
compile and run deterministic checks, but PIN-dependent and interactive hardware
scenarios are unavailable until Windows ACL-aware secret and acknowledgment
input is implemented. The read-only information scenario does not need this
input. Cross-platform compilation does not qualify physical Windows device I/O.
The client package currently also inherits its PC/SC dependency's cgo build
requirement on macOS and Linux, even when only USB is selected at runtime.
The standalone HID/USB suites retain their existing no-cgo coverage; this
increment does not change that production client dependency.

An interactive marker identifies the current phase and a fresh random token.
Operator responses must match that phase, token, and exact target. Responses
from an earlier phase cannot authorize a later operation. Reconnection requires
an explicitly selected replacement endpoint, and reset requires a distinct
`RESET` confirmation before the physical power cycle. Keep the other cards
unchanged during enrollment. The controller should already be polling before
reconnection so it can submit reset within the authenticator's power-up window.
Waiting for a chat response after reconnecting may miss that window.
The harness gates fresh initialization and the Reset facade call within eight
seconds of observed reappearance, then allows a separate bounded wait for touch
and the response. This timing evidence describes the facade call and observed
inventory, not native syscall entry or the exact physical power-up instant.

The acknowledgment JSON has the following shape; all placeholders refer to the
current invocation, and selectors stay in the protected file:

```json
{"phase":"reset-confirm","token":"<current marker token>","target_id":"<exact selected endpoint>","approve":true,"confirm":"RESET"}
```

The fixed phases are `persistence-unplug`, `persistence-replug`, `reset-confirm`,
`reset-unplug`, and `reset-replug`. Replug responses additionally require
`endpoint_id` with the newly enrolled exact endpoint. Write acknowledgments by
atomic replacement of a 0600 regular file. An old phase/token is ignored; a
matching response with the wrong target or declined approval is rejected.

For a complete known-PIN qualification, run credential lifecycle and persistence,
then PIN change/restoration. Run reset only when existing FIDO data may be lost.
After a successful reset, run PIN setup separately if the desired final state is
a configured PIN. Neither a later PIN setup nor a later successful cleanup
turns an earlier failed scenario into a pass.

## State and evidence

Registration uses ES256/P-256. Assertion validation checks the credential ID,
RP ID hash, requested user-presence/user-verification flags, and the signature
over authenticator data and the fresh challenge hash. Counter validation permits
an authenticator that does not implement a counter, and checks advancement when
the previous or current value is nonzero. This is a functional diagnostic, not
an attestation-trust or FIDO certification suite.

The random test RP ID is 31 ASCII bytes: an unpadded base32 encoding of a
128-bit nonce followed by `.test`. CTAP 2.2 section 6.8.7 permits stored RP
display identifiers to be truncated to a minimum of 32 bytes during credential
enumeration. Keeping this fixture below that bound makes exact display-ID
readback valid; readback also requires the full RP SHA-256 hash and exact
credential/user IDs. This scenario does not qualify long-RP display truncation.

Credential cleanup is registered immediately after a credential ID is returned.
It targets only that invocation's credential and uses an independent bounded
cleanup context. Cleanup and explicit session Close errors remain failures,
including when a later cleanup succeeds. If registration delivery is uncertain
and no credential ID was returned, the harness records that limitation; it does
not delete unrelated credentials to obtain an apparently clean result.

PIN and reset postconditions use newly opened SDK sessions so cached GetInfo
state cannot qualify a change. Reports contain fixed operation/status evidence,
Boolean observations, and counters, without PINs, endpoint IDs, full serials,
credential IDs, raw protocol payloads, or unredacted traces.

Readback failures additionally record a fixed numeric category, row/match counts,
and Boolean RP/user/hash comparisons. Category meanings are: 0 success, 1 SDK
List error, 2 missing credential ID, 3 duplicate credential ID, 4 RP mismatch,
5 user mismatch, 6 both bindings mismatched, 7 missing List result, and 8 RP-hash
mismatch. These observations diagnose failures without printing the compared
values. A matching
RP hash does not substitute for the required exact RP and user bindings.

Reset invalidates existing FIDO credentials, including U2F credentials, and
removes discoverable credentials. It has no automatic rollback. Reset is never
an implicit setup or cleanup operation. A separate, explicitly selected PIN-set
run can configure the known PIN afterward; that does not restore credentials.

## Specification basis

- CTAP 2.2, sections 6.1 and 6.2: registration and assertion operations.
- CTAP 2.2, sections 6.5.5.5 and 6.5.5.6: setting and changing a PIN.
- CTAP 2.2, section 6.6: destructive reset, user interaction, and the USB
  power-up window.
- CTAP 2.2, section 6.8.7: permitted RP display-ID truncation during credential
  management, and use of full RP identifiers for protocol comparisons.
- WebAuthn authenticator-data and assertion-verification rules: RP hash,
  flags, signature input, and signature-counter handling.

See the [CTAP 2.2 specification](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html)
for the normative command definitions. Device-reported capabilities and policies
determine which scenarios can run.
