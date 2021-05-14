package fakeauditlog

import (
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"google.golang.org/grpc/codes"
)

type AuditLog struct {
	fields logrus.Fields

	emitedFields logrus.Fields
	err          error
	batchEntries []map[string]string
}

func New() *AuditLog {
	return &AuditLog{
		fields:       logrus.Fields{},
		emitedFields: logrus.Fields{},
		batchEntries: []map[string]string{},
	}
}

func (a *AuditLog) AddFields(fields logrus.Fields) {
	for k, v := range fields {
		a.fields[k] = v
	}
}

func (a *AuditLog) Emit(fields logrus.Fields) {
	a.emitedFields = fields
}

func (a *AuditLog) GetEmitedFields() map[string]string {
	emitedFields := make(map[string]string)

	appendFields(emitedFields, a.fields)
	appendFields(emitedFields, a.emitedFields)

	return emitedFields
}

func (a *AuditLog) GetBatchEntries() []map[string]string {
	return a.batchEntries
}

func (a *AuditLog) EmitBatch(status *types.Status, fields logrus.Fields) {
	m := map[string]string{
		"status_code":    codes.Code(status.Code).String(),
		"status_message": status.Message,
	}
	for k, v := range fields {
		m[k] = fmt.Sprintf("%v", v)
	}
	a.batchEntries = append(a.batchEntries, m)
}

func (a *AuditLog) EmitError(err error) {
	a.err = err
}

func (a *AuditLog) Reset() {
	a.emitedFields = logrus.Fields{}
	a.fields = logrus.Fields{}
	a.batchEntries = []map[string]string{}
	a.err = nil
}

func appendFields(m map[string]string, fields logrus.Fields) {
	for k, v := range fields {
		m[k] = fmt.Sprintf("%v", v)
	}
}
