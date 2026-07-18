package sqlstorev2

import (
	"path/filepath"
	"testing"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

func openGormV2(t *testing.T) *gorm.DB {
	dbPath := filepath.ToSlash(filepath.Join(t.TempDir(), "m.sqlite3"))
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{Logger: gormlogger.Discard})
	require.NoError(t, err)
	return db
}

func TestMigrateDBFreshDatabase(t *testing.T) {
	log, _ := test.NewNullLogger()
	db := openGormV2(t)

	require.NoError(t, migrateDB(db, "sqlite3", false, log))

	// Migration row exists at the latest version.
	var m Migration
	require.NoError(t, db.First(&m).Error)
	require.Equal(t, latestSchemaVersion, m.Version)
	require.Equal(t, codeVersion.String(), m.CodeVersion)

	// The manual join-table index exists.
	require.True(t, db.Migrator().HasIndex("federated_registration_entries", "idx_federated_registration_entries_registered_entry_id"))

	// Second call is a no-op (already at latest).
	require.NoError(t, migrateDB(db, "sqlite3", false, log))
}

// TestMigrateDBUpgradeChain exercises the forward-migration loop in
// migrateDB (migrateVersion -> migrateToV24 -> migrateToV25) by seeding a
// migrations row at schema version 23 (the oldest version still eligible for
// migration; anything older requires a previous SPIRE release per
// lastMinorReleaseSchemaVersion) against an otherwise-current schema, then
// driving migrateDB forward to latestSchemaVersion.
func TestMigrateDBUpgradeChain(t *testing.T) {
	log, _ := test.NewNullLogger()
	db := openGormV2(t)

	// Establish the full current schema (all tables/columns already at head),
	// then roll only the tracked migration version back to simulate an
	// existing database left behind by an older SPIRE release.
	require.NoError(t, migrateDB(db, "sqlite3", false, log))

	var seeded Migration
	require.NoError(t, db.First(&seeded).Error)
	require.NoError(t, db.Model(&Migration{}).Where("id = ?", seeded.ID).Updates(map[string]any{
		"version":      lastMinorReleaseSchemaVersion,
		"code_version": "1.8.0",
	}).Error)

	require.NoError(t, migrateDB(db, "sqlite3", false, log))

	var m Migration
	require.NoError(t, db.First(&m).Error)
	require.Equal(t, latestSchemaVersion, m.Version)
	require.Equal(t, codeVersion.String(), m.CodeVersion)
}

// TestMigrateDBStampsNewerCodeVersion exercises the "schema already at latest,
// but the running code is newer than the stored code version" branch of
// migrateDB, which updates only the code_version column. This is the second of
// the two Migration Updates() sites that required an explicit WHERE clause
// under gorm v2 (global-update protection); the forward-loop test covers the
// other, so this test closes the coverage gap on this branch.
func TestMigrateDBStampsNewerCodeVersion(t *testing.T) {
	log, _ := test.NewNullLogger()
	db := openGormV2(t)

	// Establish the full current schema at the latest version.
	require.NoError(t, migrateDB(db, "sqlite3", false, log))

	// Leave the schema version at latest but roll the stored code version back
	// to an older release, so codeVersion.GT(dbCodeVersion) is true.
	var seeded Migration
	require.NoError(t, db.First(&seeded).Error)
	require.NoError(t, db.Model(&Migration{}).Where("id = ?", seeded.ID).Updates(map[string]any{
		"code_version": "1.8.0",
	}).Error)

	require.NoError(t, migrateDB(db, "sqlite3", false, log))

	var m Migration
	require.NoError(t, db.First(&m).Error)
	require.Equal(t, latestSchemaVersion, m.Version)
	require.Equal(t, codeVersion.String(), m.CodeVersion)
}
