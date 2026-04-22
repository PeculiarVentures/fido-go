# Copilot Instructions — FIDO Go Module

## Purpose

This file defines **always-on instructions** for AI agents working in this repository.

It establishes:

- architectural constraints,
- coding principles,
- protocol boundaries,
- expectations for extensibility and correctness,
- requirements for keeping documentation in sync with code,
- guidelines for writing maintainable Go code.

---

## Project Status

This project is in **active development**.

### Implications:

- Public APIs are **not yet stable**
- Refactoring and redesign are allowed and expected
- Improvements in:
  - API clarity
  - usability
  - maintainability
  - extensibility

  SHOULD be applied when identified

### AI Behavior:

AI SHOULD:

- propose and apply improvements when they clearly improve design
- simplify APIs when possible
- remove unnecessary complexity
- refactor code when it improves clarity or architecture

AI MUST:

- preserve architectural constraints (see below)
- avoid breaking changes without clear justification
- update documentation when API changes

---

# 1. Core Architectural Model

The system is a **layered, transport-agnostic FIDO/CTAP implementation**.

```
CLI / Tools
    ↓
Client (Facade API)
    ↓
CTAP Layer (CTAP1 / CTAP2)
    ↓
Wire / Framing Layer
    ↓
Transport Layer (USB / NFC / BLE)
    ↓
Device / OS
```

---

## 1.1 Layering Rules (STRICT)

AI MUST follow these constraints:

- Transport MUST NOT know about CTAP semantics
- CTAP MUST NOT depend on transport implementation details
- Wire layer MUST NOT implement protocol logic
- CLI MUST use only public APIs
- Extensions MUST NOT modify core behavior directly

If a change violates layering → **it is incorrect**

---

## 1.2 Protocol Separation

CTAP1 (U2F) and CTAP2 are **independent protocols**

### MUST:

- Implement in separate packages (`ctap1`, `ctap2`)
- Keep separate command models
- Keep separate encoders/decoders

### MUST NOT:

- Merge CTAP1 and CTAP2 into shared abstractions
- Introduce “unified command” interfaces across protocols

---

## 1.3 Transport Model

Supported transports:

- USB HID
- NFC (APDU/ISO)
- BLE

### Requirements:

- Transport is pluggable
- Transport handles framing internally
- Transport exposes raw exchange only

Transport MUST be **protocol-agnostic**

---

## 1.4 Raw Access Requirement

The system MUST support raw communication:

```go
InvokeRaw(protocol, command, payload)
```

Never remove or restrict raw access.

---

## 1.5 Capability-Based Behavior

Never assume device capabilities.

### MUST:

- Detect capabilities at runtime
- Support fallback (CTAP2 → CTAP1)
- Respect device-reported features

---

# 2. Code Writing Guidelines (CRITICAL)

## 2.1 File Size and Structure

- Files SHOULD NOT exceed ~500–600 lines
- If a file grows beyond this size → consider splitting by responsibility
- Prefer multiple small cohesive files over large “utility” files

---

## 2.2 Code Clarity

Prefer:

- simple, readable code
- explicit logic
- small focused functions

Avoid:

- overly complex abstractions
- deeply nested logic
- premature optimization

---

## 2.3 Comments

Comments MUST:

- be written in English
- follow Go conventions
- be concise and meaningful

### MUST include:

- doc comments for exported:
  - types
  - interfaces
  - functions
  - methods

- explanations for non-obvious logic

### MUST NOT:

- explain obvious code
- duplicate what code already expresses
- become verbose or redundant

---

## 2.4 Naming

Naming MUST follow Go conventions:

- clear and descriptive names
- idiomatic Go style
- correct use of exported vs unexported identifiers

Avoid:

- abbreviations that reduce clarity
- inconsistent naming
- redundant words

---

## 2.5 Interfaces (IMPORTANT)

Use interfaces for:

- public architectural boundaries
- extension points
- testability (mocking, fakes)
- decoupling between layers

### DO:

- define small, focused interfaces
- place interfaces close to where they are used
- use interfaces when they provide real value

### DO NOT:

- introduce interfaces without a clear reason
- create interfaces with a single implementation unless justified
- over-abstract simple logic

---

## 2.6 Package Design

- keep packages focused on a single responsibility
- avoid cyclic dependencies
- reflect architecture in package structure

---

# 3. Command Model

## 3.1 Typed Commands (Preferred)

Commands SHOULD be strongly typed:

```go
type Command interface {
    Protocol() ProtocolFamily
    Encode() ([]byte, error)
    DecodeResponse([]byte, any) error
}
```

---

## 3.2 Raw Commands (Required)

Always support:

```go
InvokeRaw(...)
```

---

## 3.3 Anti-Patterns

DO NOT:

- expose only raw API
- merge CTAP1/CTAP2 commands
- hide protocol differences

---

# 4. Error Handling

Errors MUST be structured and layered:

- Transport errors
- Protocol errors (CTAP status codes)
- Decode/validation errors

Do NOT return ambiguous or generic errors.

---

# 5. Middleware & Cross-Cutting Concerns

Cross-cutting features MUST use middleware:

Examples:

- tracing
- logging
- retries
- vendor quirks

Do NOT embed these directly into protocol logic.

---

# 6. Extensions (Vendor Support)

Vendor-specific behavior MUST:

- be isolated from core
- be registered dynamically
- not modify base protocol logic

---

# 7. Tracing & Debugging

Tracing is a first-class feature.

### MUST:

- support raw payload tracing
- support decoded protocol tracing
- be transport-independent

Tracing MUST NOT change system behavior.

---

# 8. CLI Rules

CLI MUST:

- use public API only
- support raw operations
- support diagnostics and tracing

CLI MUST NOT:

- bypass architecture
- directly access transport internals

---

# 9. Version Handling

The system MUST:

- explicitly support multiple CTAP versions
- avoid assuming latest version behavior
- track capabilities per device

---

# 10. Documentation Synchronization (CRITICAL)

Documentation MUST stay consistent with code.

## 10.1 Global Rule

After any code change, AI MUST verify whether updates are required in:

- root `README.md`
- module-level `README.md`
- `copilot-instructions.md`
- `*.instructions.md`
- `docs/`

If documentation is outdated → it MUST be updated.

---

## 10.2 Trigger Conditions

Documentation MUST be reviewed when:

- public API changes
- architecture changes
- new modules/packages are added
- transport behavior changes
- CTAP behavior changes
- CLI behavior changes
- instructions no longer match implementation

---

## 10.3 README Rules

README files MUST:

- be concise
- reflect current state
- describe purpose and usage
- avoid duplication of detailed specs
- link to deeper documentation

---

## 10.4 AI Behavior

AI MUST:

- update documentation when needed
- avoid unnecessary changes
- remove outdated content
- keep documentation clear and minimal

---

# 11. AI Agent Guidelines

## When Writing Code

AI MUST:

- respect architecture layers
- follow code guidelines
- use appropriate abstractions
- maintain raw access

---

## When Modifying Code

AI MUST:

- identify affected layer
- avoid cross-layer violations
- preserve or improve design
- verify documentation consistency

---

## When Designing Features

AI MUST:

- consider extensibility
- consider protocol evolution
- consider transport independence
- consider API clarity

---

## When Unsure

Prefer:

- explicit implementation
- separation of concerns
- simpler design

Avoid:

- guessing behavior
- inventing unnecessary abstractions

---

# 12. Forbidden Patterns

AI MUST NOT introduce:

- transport-aware CTAP logic
- unified CTAP1/CTAP2 abstractions
- hidden protocol switching
- hardcoded device assumptions
- vendor hacks in core logic

---

# 13. Summary

This project is built around:

- strict layering
- protocol isolation
- transport abstraction
- extensibility via composition
- strong debugging capabilities
- clean, maintainable code
- synchronized documentation

These are **non-negotiable constraints**.

AI agents must treat them as **hard rules**, not suggestions.
