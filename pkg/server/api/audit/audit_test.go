package audit_test

import (
	"fmt"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/server/api/audit"
	"github.com/spiffe/spire/test/spiretest"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestLog(t *testing.T) {
	log, logHook := test.NewNullLogger()

	auditLog := audit.New(log)

	t.Run("with error", func(t *testing.T) {
		auditLog.WithError(status.Error(codes.Internal, "some error")).Send()
		spiretest.AssertLogs(t, logHook.AllEntries(), []spiretest.LogEntry{
			{
				Level:   logrus.InfoLevel,
				Message: "Audit log",
				Data: logrus.Fields{
					"status":         "error",
					"type":           "audit",
					"status_code":    "Internal",
					"status_message": "some error",
				},
			},
		})
	})

	logHook.Reset()

	t.Run("with field", func(t *testing.T) {
		auditLog.WithField("key", "value").Send()
		spiretest.AssertLogs(t, logHook.AllEntries(), []spiretest.LogEntry{
			{
				Level:   logrus.InfoLevel,
				Message: "Audit log",
				Data: logrus.Fields{
					"type": "audit",
					"key":  "value",
				},
			},
		})
	})

	logHook.Reset()

	t.Run("with fields", func(t *testing.T) {
		auditLog.WithFields(logrus.Fields{
			"k1": "v1",
			"k2": "v2",
		}).Send()
		spiretest.AssertLogs(t, logHook.AllEntries(), []spiretest.LogEntry{
			{
				Level:   logrus.InfoLevel,
				Message: "Audit log",
				Data: logrus.Fields{
					"type": "audit",
					"k1":   "v1",
					"k2":   "v2",
				},
			},
		})
	})

	logHook.Reset()

	t.Run("with status", func(t *testing.T) {
		s := &types.Status{Code: int32(codes.Internal), Message: "some msj"}
		auditLog.WithStatus(s).Send()
		spiretest.AssertLogs(t, logHook.AllEntries(), []spiretest.LogEntry{
			{
				Level:   logrus.InfoLevel,
				Message: "Audit log",
				Data: logrus.Fields{
					"status":         "error",
					"type":           "audit",
					"status_code":    "Internal",
					"status_message": "some msj",
				},
			},
		})
	})
}

func Test(t *testing.T) {
	m := &types.Entry{
		Id:       "foo",
		SpiffeId: &types.SPIFFEID{TrustDomain: "td", Path: "foo"},
		Selectors: []*types.Selector{
			{Type: "a", Value: "1"},
		},
	}

	m.ProtoReflect().Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		fmt.Printf("FieldName: %q - Value %s \n", fd.JSONName(), v.String())

		return true
	})
}

// func TestLog(t *testing.T) {
// log, logHook := test.NewNullLogger()

// auditLog := audit.New(log)

// m := &types.Entry{
// Id:       "foo",
// SpiffeId: &types.SPIFFEID{TrustDomain: "td", Path: "foo"},
// Selectors: []*types.Selector{
// {Type: "a", Value: "1"},
// },
// }
// auditLog.AppendRequestFields(m, map[string]bool{
// "id":        true,
// "spiffe_id": true,
// "selectors": true,
// }).Send()

// spiretest.AssertLogs(t, logHook.AllEntries(), []spiretest.LogEntry{
// {
// Level:   logrus.InfoLevel,
// Message: "Audit log",
// Data: logrus.Fields{
// "Body": "foo",
// },
// },
// })
// auditLog.WithError(status.Error(codes.Internal, "some error")).Send()
// }

type message struct {
	proto.Message

	Body       string
	List       []string
	SubMessage *message
}
