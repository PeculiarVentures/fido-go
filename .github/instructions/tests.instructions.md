---
name: "Testing Strategy and Rules"
description: "Rules for creating tests, test organization, mocking strategies, and testing patterns across layers."
applyTo: "**/*_test.go"
---

# Testing Instructions — FIDO Go Module

## Scope

Testing strategy covers:

- unit tests for individual components
- integration tests for layer interactions
- protocol compliance tests
- device communication tests
- CLI tool testing

## Layered Testing Strategy

Each layer MUST be testable in isolation.

```
Transport Layer Tests
  ├─ Device discovery tests
  ├─ Session lifecycle tests
  └─ Raw Exchange tests (no protocol knowledge)

Wire Layer Tests
  ├─ Fragmentation/reassembly tests
  ├─ Packet structure tests
  └─ Edge case tests (malformed packets)

CTAP1 Layer Tests
  ├─ Command encoding tests
  ├─ Response decoding tests
  └─ Error handling tests

CTAP2 Layer Tests
  ├─ CBOR encoding/decoding tests
  ├─ Command execution tests
  └─ Extension handling tests

Client/Facade Tests
  ├─ Authentication flow tests
  ├─ Registration flow tests
  └─ Capability detection tests

CLI Tests
  ├─ Command parsing tests
  ├─ Output formatting tests
  └─ Error handling tests
```

## Unit Test Requirements

### Test Organization

```go
package <layer>_test

import (
    "testing"
    "<module>/<layer>"
)

func TestFeature(t *testing.T) {
    // Arrange
    // Act
    // Assert
}
```

### Naming Convention

- File: `<component>_test.go`
- Test function: `Test<Component><Behavior>`

Examples:

```go
func TestRegisterCommand_Encode(t *testing.T)
func TestRegisterCommand_EncodeWithInvalidInput(t *testing.T)
func TestSession_ExchangeWithTimeout(t *testing.T)
func TestFragmentation_LargePayload(t *testing.T)
```

### Test Structure

Follow AAA pattern (Arrange-Act-Assert):

```go
func TestSomething(t *testing.T) {
    // Arrange: Set up test data and dependencies
    cmd := ctap1.NewRegisterCommand(...)

    // Act: Execute the operation
    encoded, err := cmd.Encode()

    // Assert: Verify results
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if len(encoded) == 0 {
        t.Error("encoded data is empty")
    }
}
```

## Mocking Strategy

### Protocol-Agnostic Mocks

Transport layer MUST use synthetic mocks:

```go
type MockSession struct {
    ExchangeFunc func(ctx context.Context, req []byte) ([]byte, error)
}

func (m *MockSession) Exchange(ctx context.Context, req []byte) ([]byte, error) {
    return m.ExchangeFunc(ctx, req)
}
```

Do NOT:

- call real devices in unit tests
- require real hardware
- make network calls
- use system-dependent features

### CTAP1 Mocks

CTAP1 tests use synthetic session mocks:

```go
func TestRegisterCommand_Decode(t *testing.T) {
    // Synthetic response from U2F device
    response := []byte{
        0x04, // Response type
        // ... attestation data
        0x90, 0x00, // Status: success (SW1|SW2)
    }

    cmd := &RegisterCommand{}
    var result RegisterResponse

    err := cmd.DecodeResponse(response, &result)
    if err != nil {
        t.Fatalf("decode error: %v", err)
    }
}
```

### CTAP2 Mocks

CTAP2 tests use synthetic responses:

```go
func TestGetInfoCommand_Decode(t *testing.T) {
    // Synthetic response from CTAP2 device
    response := []byte{
        0x00, // Status: success
        // ... CBOR-encoded capabilities
    }

    cmd := &GetInfoCommand{}
    var caps AuthenticatorCapabilities

    err := cmd.DecodeResponse(response, &caps)
    if err != nil {
        t.Fatalf("decode error: %v", err)
    }
}
```

## No Real Device Tests (in unit tests)

Unit tests MUST NOT:

- require physical devices
- call real transport layers
- access USB, NFC, BLE
- depend on specific devices

INSTEAD:

- use mock sessions
- use test vectors from specs
- use synthetic payloads
- test protocol logic only

## Integration Tests

Separate integration tests MAY:

- use real devices (if available)
- test layer interactions
- test end-to-end flows
- require specific hardware

Organization:

```
integration_tests/
  transport_integration_test.go
  protocol_integration_test.go
  cli_integration_test.go
```

Mark with build tags:

```go
//go:build integration

func TestAuthenticateWithRealDevice(t *testing.T) {
    // Requires device to be connected
}
```

Run integration tests separately:

```bash
go test -tags=integration ./...
```

## Protocol Compliance Tests

### Test Vectors

Use official test vectors from FIDO specifications:

```go
func TestCTAP2GetInfo_WithOfficialVector(t *testing.T) {
    // Test vector from CTAP2 spec
    response := []byte{ /* ... */ }

    cmd := &GetInfoCommand{}
    var caps AuthenticatorCapabilities

    if err := cmd.DecodeResponse(response, &caps); err != nil {
        t.Fatalf("failed to decode official test vector: %v", err)
    }

    // Verify expected capabilities
    if len(caps.Versions) == 0 {
        t.Error("no versions in response")
    }
}
```

### Edge Cases

Test protocol edge cases:

```go
func TestCBORDecoding_WithNullValues(t *testing.T) {
    // Null in optional field
}

func TestCBORDecoding_WithMissingFields(t *testing.T) {
    // Mandatory field missing
}

func TestFragmentation_SingleByte(t *testing.T) {
    // Minimum payload size
}

func TestFragmentation_ExactBoundary(t *testing.T) {
    // Payload exactly at transport limit
}

func TestReassembly_OutOfOrderPackets(t *testing.T) {
    // Packets arrive in different order
}

func TestReassembly_DuplicatePackets(t *testing.T) {
    // Duplicate packets in stream
}
```

## Error Handling Tests

Test all error paths:

```go
func TestRegisterCommand_DecodeWithInvalidStatus(t *testing.T) {
    response := []byte{0x6a, 0x82}  // File not found
    cmd := &RegisterCommand{}

    err := cmd.DecodeResponse(response, nil)
    if err == nil {
        t.Error("expected error for invalid status")
    }

    // Verify error type
    if _, ok := err.(*CTAP1Error); !ok {
        t.Errorf("expected CTAP1Error, got %T", err)
    }
}
```

## Concurrency Testing

For transport layer:

```go
func TestSession_ConcurrentExchange(t *testing.T) {
    // Multiple concurrent Exchange calls
    for i := 0; i < 10; i++ {
        go func(id int) {
            _, err := session.Exchange(ctx, payload)
            // ... verify
        }(i)
    }
}
```

## Context and Timeout Testing

Test context handling:

```go
func TestExchange_WithCancelledContext(t *testing.T) {
    ctx, cancel := context.WithCancel(context.Background())
    cancel()  // Cancel immediately

    _, err := session.Exchange(ctx, payload)
    if err != context.Canceled {
        t.Errorf("expected context.Canceled, got %v", err)
    }
}

func TestExchange_WithTimeout(t *testing.T) {
    ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
    defer cancel()

    _, err := session.Exchange(ctx, largePayload)
    if err != context.DeadlineExceeded {
        t.Errorf("expected context.DeadlineExceeded, got %v", err)
    }
}
```

## CLI Testing

CLI tests use mock client:

```go
func TestAuthenticateCommand_WithValidInput(t *testing.T) {
    mockClient := &MockClient{
        AuthenticateFunc: func(...) (*AuthResult, error) {
            return &AuthResult{...}, nil
        },
    }

    cmd := NewAuthenticateCommand(mockClient)
    output := captureOutput(func() {
        err := cmd.Run([]string{
            "--challenge", base64.StdEncoding.EncodeToString(challenge),
        })
        if err != nil {
            t.Fatalf("command failed: %v", err)
        }
    })

    // Verify output format
    if !strings.Contains(output, "success") {
        t.Error("success message not in output")
    }
}
```

## Test Data

Store test data in subdirectories:

```
ctap2/
  encoding/
    testdata/
      valid_get_info_response.bin
      invalid_cbor.bin
      malformed_response.bin
```

Load test data:

```go
func TestDecoding_WithValidResponse(t *testing.T) {
    data := mustReadFile(t, "testdata/valid_get_info_response.bin")
    // Use data in test
}
```

## Benchmarking

Create benchmarks for performance-critical code:

```go
func BenchmarkCBOREncoding(b *testing.B) {
    cmd := &GetInfoCommand{}
    for i := 0; i < b.N; i++ {
        _, _ = cmd.Encode()
    }
}
```

Run benchmarks:

```bash
go test -bench=. -benchmem ./pkg/ctap2
```

## Coverage Requirements

Minimum coverage targets:

- Protocol encoding/decoding: 90%+
- Transport layer: 85%+
- Client/facade API: 80%+
- CLI: 75%

Generate coverage report:

```bash
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

## Test Execution

### Run all tests:

```bash
go test ./...
```

### Run specific layer tests:

```bash
go test ./pkg/ctap2/...
go test ./pkg/transport/...
```

### Run with verbose output:

```bash
go test -v ./...
```

### Run with race detection:

```bash
go test -race ./...
```

## CI/CD Testing

GitHub Actions or equivalent should:

- Run all tests with `-race` flag
- Generate coverage reports
- Run integration tests (if devices available)
- Run benchmarks and compare results
- Lint code (golangci-lint)

## Summary

**Testing = Layered, Mock-First, Protocol-Compliant**

- Unit tests use mocks, not real devices
- Test each layer independently
- Test protocol compliance with official vectors
- Test all error paths
- Test concurrency and timeouts
- CLI tests use mock client
- Separate integration tests from unit tests
- Maintain high coverage (75-90%+ per layer)
- No dependencies on specific hardware in unit tests
