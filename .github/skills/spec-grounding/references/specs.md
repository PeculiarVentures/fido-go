# Local Spec Index

Use these local HTML copies as the source of truth before consulting anything else.

## CTAP

- CTAP 2.0: `docs/raw/fido/ctap/2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html`
- CTAP 2.1: `docs/raw/fido/ctap/2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html`
- CTAP 2.2: `docs/raw/fido/ctap/2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html`
- CTAP 2.3: `docs/raw/fido/ctap/2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html`

## CTAP1 / U2F

- U2F Raw Messages 1.2: `docs/raw/fido/u2f/1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html`
- U2F Overview 1.2: `docs/raw/fido/u2f/1.2-ps-20170411/fido-u2f-overview-v1.2-ps-20170411.html`
- U2F HID Protocol 1.2: `docs/raw/fido/u2f/1.2-ps-20170411/fido-u2f-hid-protocol-v1.2-ps-20170411.html`

> If any files under `docs/raw/fido/` are missing, run `go run scripts/download_fido_specs.go` from the repository root to fetch the expected raw FIDO/CTAP specs.
>
> Note: the downloader uses the current FIDO archive structure, including paths such as `https://fidoalliance.org/specs/fido-v2.0-ps-20190130/`, `https://fidoalliance.org/specs/common-specs/`, `https://fidoalliance.org/specs/mds/`, and `https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/`.

## Supporting Specs

- Glossary: `docs/raw/fido/common-specs/fido-glossary-v2.1-ps-20220523.html`
- Registry: `docs/raw/fido/common-specs/fido-registry-v2.2-ps-20220523.html`
- Security reference: `docs/raw/fido/common-specs/fido-security-ref-v2.1-ps-20220523.html`
- Metadata service: `docs/raw/fido/mds/fido-metadata-service-v3.1-ps-20250521.html`
- Metadata statement: `docs/raw/fido/mds/fido-metadata-statement-v3.1-ps-20250521.html`

## Usage Notes

- Prefer the spec version that matches the code path under review.
- Compare adjacent CTAP versions when behavior or fields may have changed.
- Use the supporting specs for terminology, registry values, security constraints, and metadata behavior.
- If the local HTML does not answer the question, ask for clarification instead of guessing.
