package audit

import (
	"fmt"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type Log interface {
	AddEvent(fields logrus.Fields, err error, requests ...proto.Message)
	Send(log logrus.FieldLogger, err error)
}

type event struct {
	fields  logrus.Fields
	request []proto.Message
	err     error
}

func New(fields logrus.Fields) Log {
	fields["type"] = "audit"
	log := &log{
		fields: fields,
	}

	return log
}

type log struct {
	fields logrus.Fields
	events []*event
}

func (l *log) AddEvent(fields logrus.Fields, err error, requests ...proto.Message) {
	event := &event{
		fields:  fields,
		request: requests,
		err:     err,
	}
	l.events = append(l.events, event)
}

func appendError(fields logrus.Fields, err error) {
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
}

func appendRequestBody(fields logrus.Fields, req []proto.Message) {
	if len(req) == 0 {
		return
	}
	reqBody := ""
	for _, m := range req {
		reqBody += fmt.Sprintf("%+v", m)
	}

	fields["request-body"] = reqBody
}

func appendFields(fields logrus.Fields, newFields logrus.Fields) {
	for key, value := range newFields {
		fields[key] = value
	}
}

func (l *log) Send(log logrus.FieldLogger, err error) {
	for _, e := range l.events {
		fields := e.fields
		appendFields(fields, l.fields)
		appendError(fields, err)
		appendRequestBody(fields, e.request)

		eLog := log.WithFields(e.fields)
		eLog.Info("Audit log")
	}
}
