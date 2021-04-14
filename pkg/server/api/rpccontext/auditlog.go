package rpccontext

import (
	"context"

	"github.com/spiffe/spire/pkg/server/api/audit"
)

type auditLogKey struct{}

func WithAuditLog(ctx context.Context, auditLog audit.Log) context.Context {
	return context.WithValue(ctx, auditLogKey{}, auditLog)
}

func AuditLog(ctx context.Context) audit.Log {
	auditLog, ok := ctx.Value(auditLogKey{}).(audit.Log)
	if ok {
		return auditLog
	}

	panic("RPC context missing audit log")
}
