package ctap2

import "fmt"

// Error reports a CTAP2 status-code failure.
type Error struct {
	Code    uint8
	Message string
}

// Error returns the CTAP2 error message.
func (err *Error) Error() string {
	message := err.Message
	if message == "" {
		message = statusText(err.Code)
	}
	return fmt.Sprintf("ctap2: status 0x%02x: %s", err.Code, message)
}

func statusText(code uint8) string {
	switch code {
	case 0x00:
		return "success"
	case 0x01:
		return "invalid command"
	case 0x02:
		return "invalid parameter"
	case 0x03:
		return "invalid length"
	case 0x04:
		return "invalid sequence"
	case 0x05:
		return "timeout"
	case 0x06:
		return "channel busy"
	case 0x0a:
		return "lock required"
	case 0x0b:
		return "invalid channel"
	case 0x11:
		return "CBOR unexpected type"
	case 0x12:
		return "invalid CBOR"
	case 0x14:
		return "missing parameter"
	case 0x15:
		return "limit exceeded"
	case 0x16:
		return "unsupported extension"
	case 0x17:
		return "fingerprint database full"
	case 0x18:
		return "large blob storage full"
	case 0x19:
		return "credential excluded"
	case 0x21:
		return "processing"
	case 0x22:
		return "invalid credential"
	case 0x23:
		return "user action pending"
	case 0x24:
		return "operation pending"
	case 0x25:
		return "no operations"
	case 0x26:
		return "unsupported algorithm"
	case 0x27:
		return "operation denied"
	case 0x28:
		return "key store full"
	case 0x2b:
		return "unsupported option"
	case 0x2c:
		return "invalid option"
	case 0x2d:
		return "keepalive cancel"
	case 0x2e:
		return "no credentials"
	case 0x2f:
		return "user action timeout"
	case 0x30:
		return "not allowed"
	case 0x31:
		return "PIN invalid"
	case 0x32:
		return "PIN blocked"
	case 0x33:
		return "PIN authentication invalid"
	case 0x34:
		return "PIN authentication blocked"
	case 0x35:
		return "PIN not set"
	case 0x36:
		return "pinUvAuthToken required"
	case 0x37:
		return "PIN policy violation"
	case 0x39:
		return "request too large"
	case 0x3a:
		return "action timeout"
	case 0x3b:
		return "user presence required"
	case 0x3c:
		return "user verification blocked"
	case 0x3d:
		return "integrity failure"
	case 0x3e:
		return "invalid subcommand"
	case 0x3f:
		return "user verification invalid"
	case 0x40:
		return "unauthorized permission"
	case 0x7f:
		return "other error"
	case 0xdf:
		return "specification-defined error boundary"
	case 0xe0:
		return "extension-specific error"
	case 0xef:
		return "extension-specific error boundary"
	case 0xf0:
		return "vendor-specific error"
	case 0xff:
		return "vendor-specific error boundary"
	default:
		return "unknown status"
	}
}
