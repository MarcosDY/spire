package audit

import (
	"context"
	"fmt"

	"github.com/gofrs/uuid"
	"github.com/golang/protobuf/proto"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/peertracker"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Log struct {
	RequestID string
	// fields    logrus.Fields
	log logrus.FieldLogger
}

func New(ctx context.Context) (Log, error) {
	requestID, err := uuid.NewV4()
	if err != nil {
		return Log{}, err
	}

	log := Log{
		RequestID: requestID.String(),
		log:       rpccontext.Logger(ctx),
	}

	fields := logrus.Fields{
		"request-id": requestID.String(),
		"type":       "audit",
		"status":     "success",
	}
	// Logger contains all caller information for remote callers.
	// It is done on Preprocess
	if rpccontext.CallerIsLocal(ctx) {
		fields = fieldsFromContext(ctx)
	}

	log = log.WithFields(fields)

	return log, nil
}

func (l Log) WithFields(fields logrus.Fields) Log {
	l.log = l.log.WithFields(fields)
	return l
}

func (l Log) WithField(key string, value interface{}) Log {
	l.log = l.log.WithField(key, value)
	return l
}

func (l Log) WithError(err error) Log {
	fields := logrus.Fields{}
	statusErr, ok := status.FromError(err)
	switch {
	case !ok:
		fields["status"] = "success"
	case statusErr.Code() == codes.OK:
		fields["status"] = "success"
	default:
		fields["status"] = "error"
		fields["status-code"] = statusErr.Code()
		fields["status-message"] = statusErr.Message()
	}

	l.log = l.log.WithFields(fields)
	return l
}

func (l Log) WithRequestBody(req ...proto.Message) Log {
	reqBody := ""
	for _, m := range req {
		reqBody += fmt.Sprintf("{%s}", proto.CompactTextString(m))
	}

	if reqBody != "" {
		return l.WithField("request-body", reqBody)
	}

	return l

}

func (l Log) Send(req ...proto.Message) {
	l.log.Info("audit log")
}

// addCallerFields add all local caller fields
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
