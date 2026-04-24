# Security Policy

## Supported Versions

`fido-go` is currently a pre-`v1.0.0` project. Security fixes are applied to the latest development branch and to the latest tagged `v0.x` release when a release exists.

Older `v0.x` releases may receive fixes when practical, but users should generally upgrade to the latest available tag.

## Reporting a Vulnerability

Do not open a public issue for suspected vulnerabilities.

Report security issues privately by emailing `support@peculiarventures.com` with:

- affected package, command, or API;
- a concise impact description;
- reproduction steps or proof of concept when available;
- affected versions, commit hashes, or tags;
- whether the issue involves PINs, credential material, authenticator state, or raw trace output.

Expected handling:

- We will acknowledge receipt when possible.
- We will investigate and coordinate a fix before public disclosure.
- We will publish release notes or advisories for confirmed issues that affect users.

## Sensitive Data Expectations

Please avoid sending real PINs, private keys, production credentials, or authenticator secrets in reports. Synthetic test data and redacted traces are preferred.
