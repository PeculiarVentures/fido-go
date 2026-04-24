// Package ctap1 implements the CTAP1 / U2F Version, Register, and Authenticate
// commands plus CTAP1 status-word decoding without depending on
// transport-specific session details.
//
// The command encoding follows the FIDO U2F raw message formats:
// https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html.
package ctap1
