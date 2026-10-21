// Package client exposes the public FIDO SDK facade built on top of transport
// sessions, middleware, and protocol-specific raw invokers.
// Explicit CTAPHID messages use the optional HIDClient extension via ExchangeHID;
// they have independent middleware and redacted trace events.
package client
