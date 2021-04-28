package rpccontext

import (
	"context"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/server/api/audit"
	"google.golang.org/protobuf/proto"
)

type auditLogKey struct{}

func WithAuditLog(ctx context.Context, auditLog audit.Log) context.Context {
	return context.WithValue(ctx, auditLogKey{}, auditLog)
}

func AddAuditLogEvent(ctx context.Context, fields logrus.Fields, err error, requests ...proto.Message) {
	log := AuditLog(ctx)
	log.AddEvent(fields, err, requests...)
}

func AuditLog(ctx context.Context) audit.Log {
	auditLog, ok := ctx.Value(auditLogKey{}).(audit.Log)
	if ok {
		return auditLog
	}

	panic("RPC context missing audit log")
}
