package fakeauditlog

import (
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
)

type AuditLog struct {
	fields logrus.Fields

	emitedFields logrus.Fields
	err          error
	status       *types.Status
}

func New() *AuditLog {
	return &AuditLog{
		fields:       logrus.Fields{},
		emitedFields: logrus.Fields{},
	}
}

func (a *AuditLog) AddFields(fields logrus.Fields) {
	a.fields = fields
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

func (a *AuditLog) EmitBatch(status *types.Status, fields logrus.Fields) {
	a.emitedFields = fields
	a.status = status
}

func (a *AuditLog) EmitError(err error) {
	a.err = err
}

func appendFields(m map[string]string, fields logrus.Fields) {
	for k, v := range fields {
		m[k] = fmt.Sprintf("%v", v)
	}
}
