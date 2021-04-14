package audit

import (
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

type Log struct {
	log logrus.FieldLogger
}

func New(log logrus.FieldLogger) Log {
	log = log.WithField("type", "audit")
	return Log{
		log: log,
	}
}

func (l Log) WithFields(fields logrus.Fields) Log {
	l.log = l.log.WithFields(fields)
	return l
}

func (l Log) WithField(key string, value interface{}) Log {
	l.log = l.log.WithField(key, value)
	return l
}

func (l Log) WithStatus(s *types.Status) Log {
	err := status.Error(codes.Code(s.Code), s.Message)
	return l.WithError(err)
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
		fields["status_code"] = statusErr.Code()
		fields["status_message"] = statusErr.Message()
	}

	l.log = l.log.WithFields(fields)
	return l
}

// TODO: Experimental there are issues when trying to get a proper string,
// and it may resulst in very complex code to solve it
func (l Log) WithRequestBody(m proto.Message, attrs map[string]bool) Log {
	fields := logrus.Fields{}

	pr := m.ProtoReflect()
	pr.Range(func(d protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		if ok := attrs[d.TextName()]; ok {
			key := "request_" + d.TextName()
			fields[key] = v.String()
		}

		return true
	})

	l.log = l.log.WithFields(fields)
	return l
}

func (l Log) Send() {
	l.log.Info("Audit log")
}
