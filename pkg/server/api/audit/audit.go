package audit

import (
	"context"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/peertracker"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func Send(ctx context.Context, fields logrus.Fields, err error, msg string) {
	statusErr, ok := status.FromError(err)
	switch {
	case ok:
		fields["status"] = "success"
	case statusErr.Code() == codes.OK:
		fields["status"] = "success"
	default:
		fields["status"] = "error"
		fields["status-code"] = statusErr.Code()
		fields["status-message"] = statusErr.Message()
	}
	fields["type"] = "audit"

	// Logger contains all caller information for remote callers.
	// It is done on Preprocess
	if rpccontext.CallerIsLocal(ctx) {
		addCallerFields(ctx, fields)
	}

	log := rpccontext.Logger(ctx).WithFields(fields)
	log.Info(msg)
}

// addCallerFields add all local caller fields
func addCallerFields(ctx context.Context, fields logrus.Fields) {
	callerInfo, ok := peertracker.CallerFromContext(ctx)
	if !ok {
		return
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
}
