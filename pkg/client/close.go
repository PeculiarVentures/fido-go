package client

import (
	"context"
	"errors"

	"github.com/PeculiarVentures/fido-go/pkg/transport"
)

// ContextCloser optionally exposes context-bounded transport cleanup without
// extending the required Client interface. Builtin clients implement it.
type ContextCloser interface {
	CloseContext(context.Context) error
}

// CloseContext forwards native context-aware cleanup. Legacy sessions without
// transport.ContextCloser return ErrUnsupported; callers may use Close to wait
// for their synchronous cleanup instead. No detached cleanup worker is created.
func (client *client) CloseContext(ctx context.Context) error {
	if closer, ok := client.session.(transport.ContextCloser); ok {
		return closer.CloseContext(ctx)
	}
	return transport.Wrap("close client with context", transport.Unsupported(errors.New("client: session does not support context-aware cleanup")))
}

var _ ContextCloser = (*client)(nil)
