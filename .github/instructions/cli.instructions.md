---
name: "CLI Tool Rules"
description: "Rules for implementing command-line tools and user-facing interfaces that consume the public API."
applyTo: "cmd/**/*.go,**/cli/**/*.go"
---

# CLI Instructions — FIDO Go Module

## Scope

CLI code covers:

- command-line tool implementations
- user-facing interfaces and commands
- input/output formatting
- configuration and flag handling
- debugging and diagnostic commands

## Hard Boundary: Public API Only

CLI code MUST:

- use **public API only**
- import only from `pkg/client` (facade)
- support raw operations for debugging
- never bypass architecture

CLI code MUST NOT:

- directly access transport internals
- import from `pkg/transport`, `pkg/wire` directly
- use unexported functions
- circumvent protocol layering

## Public API Usage

Example:

```go
import "github.com/fido-go/pkg/client"

// Good: Use public client API
client := client.New(...)
result, err := client.Authenticate(ctx, challenge, options)

// BAD: Direct transport access - NEVER
import "github.com/fido-go/pkg/transport"  // ❌
session, err := transport.OpenUSB(...)      // ❌
```

## Command Categories

### 1. Authentication Commands

- `authenticate`: Perform user authentication
- `register`: Register new credential
- `reset`: Reset authenticator

Example:

```
fido-go authenticate --challenge <base64> --app-id <url>
fido-go register --user-name <name> --user-id <id>
```

### 2. Device Commands

- `list`: Enumerate connected devices
- `info`: Get device capabilities
- `version`: Query device version

Example:

```
fido-go list
fido-go info --device-id <id>
```

### 3. Diagnostic Commands

- `trace`: Enable raw payload tracing
- `debug`: Debug mode output
- `raw`: Send raw CTAP commands

Example:

```
fido-go trace authenticate ...  # Show all payloads
fido-go raw --protocol ctap2 --command <bytes>
```

### 4. Configuration Commands

- `config`: Display/set configuration
- `pin`: Manage device PIN
- `reset`: Factory reset device

## Input/Output

### Output Formats

Support multiple output formats:

- **human**: Human-readable (default)
- **json**: JSON structured output
- **raw**: Raw bytes (for debugging)

Example:

```
fido-go info --format json
fido-go trace --format raw > trace.bin
```

### Error Output

Errors MUST:

- be clear and actionable
- include error codes where relevant
- suggest next steps
- be sent to stderr

Example:

```
Error: Device not found
  Devices found: none
  Run 'fido-go list' to see available devices
```

### Interactive Prompts

For PIN entry or user confirmation:

- Use standard input
- Support non-interactive mode (--no-interactive)
- Provide sensible defaults
- Don't hang waiting for input in CI environments

## Raw Operations (Debugging)

CLI MUST support raw CTAP commands:

```
fido-go raw --protocol ctap2 --command-code 4 --params '{"1": "FIDO_2_0"}'
fido-go raw --protocol ctap1 --command-code 1 --payload <bytes>
```

This enables:

- protocol testing
- vendor extension exploration
- debugging device issues
- protocol analysis

Raw operations MUST:

- accept binary or hex-encoded payloads
- return raw responses (hex or raw)
- not interpret semantics
- support full tracing

## Configuration and Flags

### Global Flags

```
--device-id <id>           Select specific device
--timeout <duration>       Command timeout (default: 30s)
--verbose                  Verbose output
--debug                    Debug mode (additional logging)
--format <format>          Output format (human/json/raw)
--no-interactive           Non-interactive mode
```

### Per-Command Flags

Document flags per command. Use consistent naming:

- `--challenge-file` not `--file`
- `--user-name` not `--name`
- `--output-file` not `--out`

Use sensible defaults (especially for paths).

## Tracing and Debugging

CLI MUST support transparent tracing:

```
fido-go --verbose authenticate ...
fido-go trace authenticate ...
```

Output SHOULD include:

- Raw payloads sent to device
- Raw payloads received from device
- Protocol-level decoded operations (with device permission)
- Timing and latency information

Tracing MUST NOT change behavior (no side effects).

## Error Handling

CLI errors MUST:

- exit with appropriate codes
- provide context about what failed
- suggest remediation
- not expose stack traces (unless --debug)

Error codes:

- 0: Success
- 1: General error
- 2: Usage error (bad flags/args)
- 3: Device not found
- 4: Timeout
- 5: Protocol error
- 6: User verification failed

Example:

```go
if err != nil {
    fmt.Fprintf(os.Stderr, "Error: %v\n", err)
    os.Exit(1)  // or more specific code
}
```

## Help and Documentation

Every command MUST have:

- Short description (one line)
- Usage examples
- Flag documentation

Use standard help format:

```
Usage: fido-go authenticate [OPTIONS]

Perform user authentication with a security key.

Options:
  --challenge <base64>     Challenge data
  --app-id <url>          Application ID (for CTAP1)
  --timeout <duration>    Command timeout
  -h, --help              Show this help
```

## Version and Versioning

CLI MUST:

- report version: `fido-go version`
- include version in help output
- support version in --version flag
- handle version mismatches gracefully

## Non-Interactive Mode

For CI/automation:

- `--no-interactive` disables prompts
- Provide defaults for all inputs
- Fail clearly if user interaction required and disabled

Example:

```
fido-go authenticate --no-interactive --challenge <data>
# If PIN required and --no-interactive, exit with code 6 (user verification failed)
```

## Testing CLI

Create test packages:

```
cmd/
  authenticate/
    cmd_test.go
    output_test.go
  register/
    cmd_test.go
  list/
    cmd_test.go
  integration_test.go
```

Tests SHOULD:

- mock client API (not real devices)
- test flag parsing
- test output formatting
- test error conditions
- test interactive and non-interactive modes

Use synthetic mock clients for testing:

```go
type MockClient struct {
    AuthenticateFunc func(...) (*AuthResult, error)
}
```

## Examples

Create example commands in `examples/`:

```
examples/
  authenticate.sh
  register.sh
  list_devices.sh
  trace_command.sh
  raw_ctap2.sh
```

Examples SHOULD:

- show real-world usage
- demonstrate debugging
- explain output
- be runnable with sample devices

## Documentation

Document in README:

- Installation
- Quick start
- Available commands
- Common use cases
- Troubleshooting

Link to detailed docs instead of embedding everything.

## Summary

**CLI = Public API Consumer**

- Use public client API only
- Support raw operations for debugging
- Clear, actionable errors
- Multiple output formats
- Transparent tracing
- Non-interactive mode for automation
- Well-documented with examples
