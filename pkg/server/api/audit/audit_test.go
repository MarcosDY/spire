package audit_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/server/api/audit"
	"github.com/spiffe/spire/test/spiretest"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestLog(t *testing.T) {
	log, logHook := test.NewNullLogger()

	auditLog := audit.New(log)
	auditLog.AddFields(logrus.Fields{"key": "value"})

	t.Run("emit", func(t *testing.T) {
		auditLog.Emit(logrus.Fields{"emit": "test"})
		spiretest.AssertLogs(t, logHook.AllEntries(), []spiretest.LogEntry{
			{
				Level:   logrus.InfoLevel,
				Message: "Audit log",
				Data: logrus.Fields{
					"status": "success",
					"type":   "audit",
					"key":    "value",
					"emit":   "test",
				},
			},
		})
	})

	logHook.Reset()

	t.Run("emit batch", func(t *testing.T) {
		s := &types.Status{Code: int32(codes.OK), Message: "some message"}
		auditLog.EmitBatch(s, logrus.Fields{"emit": "no status"})

		s = &types.Status{Code: int32(codes.Internal), Message: "some error"}
		auditLog.EmitBatch(s, logrus.Fields{"emit": "internal error"})

		spiretest.AssertLogs(t, logHook.AllEntries(), []spiretest.LogEntry{
			{
				Level:   logrus.InfoLevel,
				Message: "Audit log",
				Data: logrus.Fields{
					"type":   "audit",
					"status": "success",
					"emit":   "no status",
				},
			},
			{
				Level:   logrus.InfoLevel,
				Message: "Audit log",
				Data: logrus.Fields{
					"type":           "audit",
					"emit":           "internal error",
					"status":         "error",
					"status_code":    "Internal",
					"status_message": "some error",
				},
			},
		})
	})

	logHook.Reset()

	t.Run("emit error", func(t *testing.T) {
		auditLog.EmitError(errors.New("fails"))
		auditLog.EmitError(status.Error(codes.InvalidArgument, "oh no"))

		spiretest.AssertLogs(t, logHook.AllEntries(), []spiretest.LogEntry{
			{
				Level:   logrus.InfoLevel,
				Message: "Audit log",
				Data: logrus.Fields{
					"type":           "audit",
					"key":            "value",
					"status":         "error",
					"status_code":    "Unknown",
					"status_message": "fails",
				},
			},
			{
				Level:   logrus.InfoLevel,
				Message: "Audit log",
				Data: logrus.Fields{
					"type":           "audit",
					"key":            "value",
					"status":         "error",
					"status_code":    "InvalidArgument",
					"status_message": "oh no",
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
