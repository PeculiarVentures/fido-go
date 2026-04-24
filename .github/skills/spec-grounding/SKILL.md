---
name: spec-grounding
description: "Use when code must stay aligned with a specification or standard (FIDO, CTAP, RFCs, HTML specs), when behavior is unclear, or when you need to avoid guessing and verify the normative source before changing code."
argument-hint: "Which spec, version, or section should be checked?"
---

# Spec Grounding

## When to Use

- Implementing or reviewing code that must match a standard.
- Resolving ambiguity in behavior, errors, fields, or protocol flow.
- Comparing behavior across spec versions.
- Avoiding guesses when a local source of truth exists.

## Local Sources

- The mirrored spec HTML files live under [docs/raw/fido](../../../docs/raw/fido).
- Start with [the local spec index](./references/specs.md).

## Procedure

1. Identify the spec family, version, and the exact code path under review.
2. Open the relevant local HTML spec and read the matching section, anchor, tables, examples, and nearby normative text.
3. Use supporting docs when needed:
   - glossary for terms and definitions
   - registry for enumerations and allowed values
   - security reference for security requirements
   - MDS docs for metadata-related behavior
4. If the behavior may vary by version, compare the relevant versions in `docs/raw/fido`.
5. Prefer explicit section/anchor evidence over implementation inference.
6. If the local specs do not answer the question, stop and ask for clarification instead of guessing.
7. For CTAP2 PIN/UV auth protocol changes, check CTAP 2.1 or newer sections for protocol 1/2 before editing `pkg/client` cryptographic helpers.
8. When proposing a change, state the exact spec version and section that justify it.

## Completion Checks

- The answer or change is backed by a local spec section or anchor.
- Any ambiguity is either resolved by comparison or called out explicitly.
- The outcome does not rely on assumptions that are unsupported by the spec.
