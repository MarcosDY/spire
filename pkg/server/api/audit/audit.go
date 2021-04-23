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
	requestID string
	fields    logrus.Fields
	log       logrus.FieldLogger
}

func New(ctx context.Context) (Log, error) {
	requestID, err := uuid.NewV4()
	if err != nil {
		return Log{}, err
	}

	log := Log{
		requestID: requestID.String(),
	}

	// Logger contains all caller information for remote callers.
	// It is done on Preprocess
	if rpccontext.CallerIsLocal(ctx) {
		log.fields = fieldsFromContext(ctx)
	}
	log.fields["type"] = "audit"

	log.log = rpccontext.Logger(ctx)

	return log, nil
}

func (l Log) WithFields(fields logrus.Fields) Log {
	for key, value := range fields {
		l.fields[key] = value
	}

	return l
}

func (l Log) WithField(key string, value interface{}) Log {
	l.log.WithField(key, value)
	return l
}

func (l Log) WithError(err error) Log {
	statusErr, ok := status.FromError(err)
	switch {
	case ok:
		l.fields["status"] = "success"
	case statusErr.Code() == codes.OK:
		l.fields["status"] = "success"
	default:
		l.fields["status"] = "error"
		l.fields["status-code"] = statusErr.Code()
		l.fields["status-message"] = statusErr.Message()
	}

	return l
}

func (l Log) Send(req ...proto.Message) {
	reqBody := ""
	for _, m := range req {
		reqBody += fmt.Sprintf("{%s}", proto.CompactTextString(m))
	}

	l.fields["req-body"] = reqBody

	l.log.WithFields(l.fields).Info("audit log")
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
