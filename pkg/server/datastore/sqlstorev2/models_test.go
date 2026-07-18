package sqlstorev2

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

func TestModelsAutoMigrate(t *testing.T) {
	dbPath := filepath.ToSlash(filepath.Join(t.TempDir(), "models.sqlite3"))
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{Logger: gormlogger.Discard})
	require.NoError(t, err)

	// Same set and order as the v1 createTables list.
	require.NoError(t, db.AutoMigrate(
		&Bundle{},
		&AttestedNode{},
		&AttestedNodeEvent{},
		&NodeSelector{},
		&RegisteredEntry{},
		&RegisteredEntryEvent{},
		&JoinToken{},
		&Selector{},
		&Migration{},
		&DNSName{},
		&FederatedTrustDomain{},
		&CAJournal{},
	))
}
