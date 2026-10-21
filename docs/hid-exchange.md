# Explicit CTAPHID message exchange

`client.ExchangeHID(ctx, sdk, command, payload)` sends a CTAPHID request through
an existing client session. It does not require a raw invoker, CTAP2 support,
capability probing, or a second device connection.

```go
// sdk is an already opened client.Client for a compatible USB HID endpoint.
response, err := client.ExchangeHID(ctx, sdk, 0x42, []byte{0x00})
```

The command is a logical seven-bit value. For example, `0x42` becomes `0xc2` in
the first HID packet; callers must not set the packet marker bit themselves.
The SDK exchanges the payload unchanged, handles fragmentation/reassembly, and
returns the full response payload without interpreting a CTAP status byte,
CBOR, APDU status, or vendor data. Empty request and response payloads are valid.

Logical commands `0x01` through `0x7f` are accepted except `INIT (0x06)`,
`CANCEL (0x11)`, `KEEPALIVE (0x3b)`, and `ERROR (0x3f)`. Initialization and
cancellation belong to the session; keepalive and error messages are processed
internally. Unknown request commands are left for the authenticator to reject.
Invalid API arguments return `*usb.InvalidHIDCommandError`. CTAPHID error
responses remain available as `*usb.HIDError` through `errors.As`.

## Compatibility and session lifecycle

The existing `client.Client`, `transport.Session`, `InvokeRaw`, `RawInvoker`,
and ordinary middleware interfaces are unchanged. `client.HIDClient` and
`usb.HIDSession` are optional extensions. The helper dispatches to any client
implementing `HIDClient`, including third-party implementations. The built-in
client checks its session for `usb.HIDSession`, rather than assuming support
from its USB device descriptor.

Both USB backends implement the extension. `HIDBackend` lazily initializes and
reuses a channel. The injected `usb.Backend` continues to use its configured
channel and ordinary packet command. NFC, BLE, and legacy USB sessions without
the optional extension return an error matching `transport.ErrUnsupported`.
An unsupported command on a capable device instead produces a CTAPHID error.

On a new native HID session, channel initialization ignores reports for other
channels and INIT replies with unrelated nonces. It checks readiness with an
empty PING before sending the caller's request. INIT and this readiness PING may
be retried after a busy response or a 300 ms response wait, with 50 ms between
attempts, at most 20 retries, and a total 3 s initialization deadline (or the
caller's earlier deadline). Each retry allocates a fresh channel so a delayed
readiness echo cannot contaminate the application channel. These local waits
keep the handle open. Application
requests are sent once; their errors, including `BUSY`, are returned to the
caller. Reports on the selected channel still undergo strict command, length,
and sequence validation.

Ordinary and explicit exchanges on a USB session share one serialization gate.
Cancellation or deadline expiry while queued does not interrupt another
caller's active transaction. During native HID I/O, cancellation may close the
connection, as with ordinary exchanges; open a new session for subsequent work.
Shutdown rejects new native calls immediately. Native reads use 100 ms bounded
waits so they can observe cancellation or shutdown without freeing an active
handle. Context cancellation returns promptly; physical cleanup is deferred
until outstanding native I/O finishes. `Close` waits for that cleanup and returns
its result consistently to concurrent/repeated callers. The native write API has
no cancellation operation, so `Close` may wait for an active write to finish.
Context and transport error identities are preserved for `errors.Is` / `errors.As`.

The explicit API does not affect `InvokeRaw`: a CTAP2 application command `0x42`
still travels inside `CTAPHID_CBOR`, and CTAP1 APDUs continue to use `CTAPHID_MSG`.

## Middleware and tracing

Use `client.WithHIDMiddleware(middleware.HIDMiddleware)` for explicit messages.
Its `WrapHIDExchange` receives command and payload separately. `HIDFunc` and
`ChainHID` provide the same adapter and registration-order behavior as ordinary
middleware. Existing `WithMiddleware` wrappers continue to see only ordinary
CTAP exchanges; a CTAP-specific retry or parser is not applied to vendor bytes.

`client.WithTrace(recorder)` installs tracing in both chains. Existing
`recorder.Events()` and the `TraceEvent` structure are unchanged; explicit HID
events are available from `recorder.HIDEvents()` as `HIDTraceEvent` values.
The `Command` field is the logical HID command, independent of payload contents.
The two event lists preserve ordering within their respective chains; they do
not provide a merged timeline.

Every explicit request and successful response, including an empty response,
records command, direction, and length. Since vendor payload semantics are
unknown, payloads are entirely redacted by default for all explicit commands.
`client.TraceOptions{RedactSecrets: false}` is the existing explicit unsafe
opt-in for payload recording in both chains. Returned event lists and payloads
are defensive copies. Existing CTAP tracing and sensitive-command redaction
keep their previous behavior.

## Read-only Yubico READ_CONFIG example

Select the YubiKey's FIDO HID device ID using `go run ./cmd/fidoctl devices`, then:

```sh
go run ./examples/yubikey-read-config -device-id '<device ID>'
```

The example checks the selected endpoint's Yubico vendor ID, sends logical
command `0x42` with page `0x00`, validates the response length byte, and prints
the first page as hexadecimal. It does not send a PIN or write configuration.
The example is tested with a synthetic session; running it on hardware is opt-in.

The response contains a length byte followed by Yubico TLVs. Serial-number TLV
`0x02`, pagination, and HID-to-PC/SC identity association belong in a caller's
vendor adapter, not in core transport. The generic exchange API does not restrict
vendor commands to reads; the example specifically uses only `READ_CONFIG`.

Protocol sources:

- [CTAP 2.2 Proposed Standard (2025-07-14)](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html),
  sections 11.2.4 (packet encoding), 11.2.9.1 (standard/control commands), and
  11.2.9.3 (vendor commands `0x40` through `0x7f`).
- [Yubico Management implementation](https://developers.yubico.com/yubikey-manager/API_Documentation/_modules/yubikit/management.html),
  `_ManagementCtapBackend.read_config` (`CTAP_READ_CONFIG = 0x42`).
