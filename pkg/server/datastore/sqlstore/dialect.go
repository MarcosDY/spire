package sqlstore

import "gorm.io/gorm"

type dialect interface {
	connect(cfg *configuration, isReadOnly bool) (db *gorm.DB, version string, supportsCTE bool, err error)
	isConstraintViolation(err error) bool
}
