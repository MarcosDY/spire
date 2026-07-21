package sqlstorev2

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/blang/semver/v4"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/version"
	"github.com/spiffe/spire/pkg/server/datastore/sqlcommon"
	"gorm.io/gorm"
)

const (
	// latestSchemaVersion is the latest database schema version in the code.
	latestSchemaVersion = 25

	// lastMinorReleaseSchemaVersion is the schema version supported by the last
	// minor release. Update when migrations are pruned after a minor release.
	lastMinorReleaseSchemaVersion = 23
)

// codeVersion is the current SPIRE code version.
var codeVersion = semver.MustParse(version.Version())

func migrateDB(db *gorm.DB, dbType string, disableMigration bool, log logrus.FieldLogger) (err error) {
	// The version comparison logic supports only 0.x and 1.x. Fail if we're
	// building a 2.x, so the logic gets revisited before release.
	if codeVersion.Major > 1 {
		log.Error("Migration code needs updating for current release version")
		return sqlcommon.NewSQLError("current migration code not compatible with current release version")
	}

	isNew := !db.Migrator().HasTable(&Migration{})

	if isNew {
		return initDB(db, dbType, log)
	}

	// Ensure the migrations table exists so we can check versioning.
	if err := db.AutoMigrate(&Migration{}); err != nil {
		return sqlcommon.NewWrappedSQLError(err)
	}

	migration := new(Migration)
	if err := db.Assign(Migration{}).FirstOrCreate(migration).Error; err != nil {
		return sqlcommon.NewWrappedSQLError(err)
	}

	schemaVersion := migration.Version

	log = log.WithField(telemetry.Schema, strconv.Itoa(schemaVersion))

	dbCodeVersion, err := getDBCodeVersion(*migration)
	if err != nil {
		log.WithError(err).Error("Error getting DB code version")
		return sqlcommon.NewSQLError("error getting DB code version: %v", err)
	}

	log = log.WithField(telemetry.VersionInfo, dbCodeVersion.String())

	if schemaVersion == latestSchemaVersion {
		log.Debug("Code and DB schema versions are the same. No migration needed")
		if codeVersion.GT(dbCodeVersion) {
			newMigration := Migration{
				Version:     latestSchemaVersion,
				CodeVersion: codeVersion.String(),
			}
			// gorm v2 refuses an Updates() call with no WHERE clause (global
			// update protection), unlike v1's jinzhu/gorm. Scope to the
			// singleton migration row explicitly.
			if err := db.Model(&Migration{}).Where("id = ?", migration.ID).Updates(newMigration).Error; err != nil {
				return sqlcommon.NewWrappedSQLError(err)
			}
		}
		return nil
	}

	if disableMigration {
		if err = isDisabledMigrationAllowed(codeVersion, dbCodeVersion); err != nil {
			log.WithError(err).Error("Auto-migrate must be enabled")
			return sqlcommon.NewWrappedSQLError(err)
		}
		return nil
	}

	// The DB schema version can get ahead during a cluster upgrade. If
	// compatible, warn and continue; otherwise bail (no rollbacks).
	if schemaVersion > latestSchemaVersion {
		if !isCompatibleCodeVersion(codeVersion, dbCodeVersion) {
			log.Error("Incompatible DB schema is too new for code version, upgrade SPIRE Server")
			return sqlcommon.NewSQLError("incompatible DB schema and code version")
		}
		log.Warn("DB schema is ahead of code version, upgrading SPIRE Server is recommended")
		return nil
	}

	// auto-migration enabled and schema behind: migrate forward.
	log.Info("Running migrations...")
	for schemaVersion < latestSchemaVersion {
		tx := db.Begin()
		if err := tx.Error; err != nil {
			return sqlcommon.NewWrappedSQLError(err)
		}
		schemaVersion, err = migrateVersion(tx, migration.ID, schemaVersion, log)
		if err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit().Error; err != nil {
			return sqlcommon.NewWrappedSQLError(err)
		}
	}

	log.Info("Done running migrations")
	return nil
}

func isDisabledMigrationAllowed(thisCodeVersion, dbCodeVersion semver.Version) error {
	// If auto-migrate is disabled and we're within +/- 1 minor of the stored
	// version, we're done.
	if !isCompatibleCodeVersion(thisCodeVersion, dbCodeVersion) {
		return errors.New("auto-migration must be enabled for current DB")
	}
	return nil
}

func getDBCodeVersion(migration Migration) (dbCodeVersion semver.Version, err error) {
	// default to 0.0.0; blank code version comes from pre-0.9 and fresh DBs.
	dbCodeVersion = semver.Version{}
	if migration.CodeVersion != "" {
		dbCodeVersion, err = semver.Parse(migration.CodeVersion)
		if err != nil {
			return dbCodeVersion, fmt.Errorf("unable to parse code version from DB: %w", err)
		}
	}
	return dbCodeVersion, nil
}

func isCompatibleCodeVersion(thisCodeVersion, dbCodeVersion semver.Version) bool {
	// Same major and minor +/- 1 => compatible.
	minMinor, maxMinor := min(dbCodeVersion.Minor, thisCodeVersion.Minor), max(dbCodeVersion.Minor, thisCodeVersion.Minor)
	return dbCodeVersion.Major == thisCodeVersion.Major && (minMinor == maxMinor || minMinor+1 == maxMinor)
}

func initDB(db *gorm.DB, dbType string, log logrus.FieldLogger) (err error) {
	log.Info("Initializing new database")
	tx := db.Begin()
	if err := tx.Error; err != nil {
		return sqlcommon.NewWrappedSQLError(err)
	}

	tables := []any{
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
		CAJournal{},
	}

	if err := tableOptionsForDialect(tx, dbType).AutoMigrate(tables...); err != nil {
		tx.Rollback()
		return sqlcommon.NewWrappedSQLError(err)
	}

	if err := tx.Assign(Migration{
		Version:     latestSchemaVersion,
		CodeVersion: codeVersion.String(),
	}).FirstOrCreate(&Migration{}).Error; err != nil {
		tx.Rollback()
		return sqlcommon.NewWrappedSQLError(err)
	}

	if err := addFederatedRegistrationEntriesRegisteredEntryIDIndex(tx); err != nil {
		tx.Rollback()
		return err
	}

	if err := tx.Commit().Error; err != nil {
		return sqlcommon.NewWrappedSQLError(err)
	}

	return nil
}

func tableOptionsForDialect(tx *gorm.DB, dbType string) *gorm.DB {
	// For MySQL, ensure indexes on varchar(255) strings work by setting the
	// engine/charset table options (compatibility with v1 schema).
	if dbType == sqlcommon.MySQL || dbType == sqlcommon.AWSMySQL {
		return tx.Set("gorm:table_options", "ENGINE=InnoDB  ROW_FORMAT=DYNAMIC DEFAULT CHARSET=utf8")
	}
	return tx
}

func migrateVersion(
	tx *gorm.DB, migrationID uint, currVersion int, log logrus.FieldLogger,
) (versionOut int, err error) {
	log.WithField(telemetry.VersionInfo, currVersion).Info("Migrating version")

	nextVersion := currVersion + 1
	// gorm v2 refuses an Updates() call with no WHERE clause (global update
	// protection), unlike v1's jinzhu/gorm. Scope to the singleton migration
	// row explicitly.
	if err := tx.Model(&Migration{}).Where("id = ?", migrationID).Updates(Migration{
		Version:     nextVersion,
		CodeVersion: version.Version(),
	}).Error; err != nil {
		return 0, sqlcommon.NewWrappedSQLError(err)
	}

	if currVersion < lastMinorReleaseSchemaVersion {
		return 0, sqlcommon.NewSQLError("migrating from schema version %d requires a previous SPIRE release; please follow the upgrade strategy at doc/upgrading.md", currVersion)
	}

	switch currVersion {
	case 23:
		err = migrateToV24(tx)
	case 24:
		err = migrateToV25(tx)
	default:
		err = sqlcommon.NewSQLError("no migration support for unknown schema version %d", currVersion)
	}
	if err != nil {
		return 0, err
	}

	return nextVersion, nil
}

func migrateToV24(tx *gorm.DB) error {
	// Add agent_version column to attested_node_entries table.
	if err := tx.AutoMigrate(&AttestedNode{}); err != nil {
		return sqlcommon.NewWrappedSQLError(err)
	}
	return nil
}

func migrateToV25(tx *gorm.DB) error {
	// Add additional_attributes column to registered_entries table.
	if err := tx.AutoMigrate(&RegisteredEntry{}); err != nil {
		return sqlcommon.NewWrappedSQLError(err)
	}
	return nil
}

func addFederatedRegistrationEntriesRegisteredEntryIDIndex(tx *gorm.DB) error {
	// gorm creates federated_registration_entries implicitly with primary key
	// (bundle_id, registered_entry_id). MySQL5 does not use that index
	// efficiently when joining by registered_entry_id, and there is no struct
	// to tag, so create the index explicitly. gorm v2 has no AddIndex, so issue
	// a raw CREATE INDEX. The HasIndex guard below (not an IF NOT EXISTS clause)
	// keeps this idempotent across the AutoMigrate that already ran.
	const idx = "idx_federated_registration_entries_registered_entry_id"
	if tx.Migrator().HasIndex("federated_registration_entries", idx) {
		return nil
	}
	if err := tx.Exec(
		`CREATE INDEX ` + idx + ` ON federated_registration_entries (registered_entry_id)`,
	).Error; err != nil {
		return sqlcommon.NewWrappedSQLError(err)
	}
	return nil
}
