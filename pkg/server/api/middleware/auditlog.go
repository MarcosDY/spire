package middleware

import (
	"context"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/peertracker"
	"github.com/spiffe/spire/pkg/server/api/audit"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
)

func WithAuditLog() Middleware {
	return auditlogMiddleware{}
}

type auditlogMiddleware struct {
}

func (m auditlogMiddleware) Preprocess(ctx context.Context, fullMethod string) (context.Context, error) {
	fields := logrus.Fields{}
	// Logger contains all caller information for remote callers.
	// It is done on Preprocess
	if rpccontext.CallerIsLocal(ctx) {
		for key, value := range fieldsFromContext(ctx) {
			fields[key] = value
		}
	}
	log := audit.New(fields)
	ctx = rpccontext.WithAuditLog(ctx, log)

	return ctx, nil
}

func (m auditlogMiddleware) Postprocess(ctx context.Context, fullMethod string, handlerInvokeed bool, rpcErr error) {
	auditLog := rpccontext.AuditLog(ctx)
	log := rpccontext.Logger(ctx)
	auditLog.Send(log, rpcErr)
}

// fieldsFromContext get caller fields from context
func fieldsFromContext(ctx context.Context) logrus.Fields {
	fields := logrus.Fields{}
	callerInfo, ok := peertracker.CallerFromContext(ctx)
	if !ok {
		return fields
	}

	if callerInfo.UID != 0 {
		fields["caller-uid"] = callerInfo.UID
	}
	if callerInfo.GID != 0 {
		fields["caller-gid"] = callerInfo.GID
	}
	if callerInfo.BinaryAddr != "" {
		fields["caller-addr"] = callerInfo.BinaryAddr
	}

	return fields
}
