package sqlstorev2_test

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus/hooks/test"
	v1 "github.com/spiffe/spire/pkg/server/datastore/sqlstore"
	v2 "github.com/spiffe/spire/pkg/server/datastore/sqlstorev2"
	"github.com/stretchr/testify/require"
)

// configurer is satisfied by both the v1 and v2 plugins.
type configurer interface {
	Configure(ctx context.Context, hcl string) error
	Close() error
}

// affinity maps a declared SQLite column type to its type affinity, which is
// the only thing SQLite actually enforces. This absorbs the cosmetic
// varchar(255)->text, bool->numeric, bigint->integer differences between the
// v1 (jinzhu) and v2 (gorm.io) DDL generators.
func affinity(declared string) string {
	d := strings.ToUpper(declared)
	switch {
	case strings.Contains(d, "INT"):
		return "INTEGER"
	case strings.Contains(d, "CHAR"), strings.Contains(d, "CLOB"), strings.Contains(d, "TEXT"):
		return "TEXT"
	case strings.Contains(d, "BLOB"), d == "":
		return "BLOB"
	case strings.Contains(d, "REAL"), strings.Contains(d, "FLOA"), strings.Contains(d, "DOUB"):
		return "REAL"
	default:
		return "NUMERIC"
	}
}

// semanticSchema migrates a fresh sqlite DB through ds, then returns a
// canonical, order-independent description of the resulting schema.
func semanticSchema(t *testing.T, ds configurer, dbPath string) string {
	t.Helper()
	hcl := `database_type = "sqlite3"` + "\n" + `connection_string = "` + dbPath + `"` + "\n"
	require.NoError(t, ds.Configure(context.Background(), hcl))
	require.NoError(t, ds.Close())

	db, err := sql.Open("sqlite3", dbPath)
	require.NoError(t, err)
	defer db.Close()

	trows, err := db.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	require.NoError(t, err)
	var tables []string
	for trows.Next() {
		var n string
		require.NoError(t, trows.Scan(&n))
		tables = append(tables, n)
	}
	require.NoError(t, trows.Err())
	trows.Close()

	var b strings.Builder
	for _, tbl := range tables {
		// Columns: name : affinity : notnull. PK membership is compared as a
		// set below (composite PK column order differs between v1 and v2 but is
		// semantically irrelevant), so pk is captured separately, not inline.
		crows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%q)", tbl))
		require.NoError(t, err)
		var cols []string
		var pkCols []string
		for crows.Next() {
			var cid, notnull, pk int
			var name, ctype string
			var dflt sql.NullString
			require.NoError(t, crows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk))
			cols = append(cols, fmt.Sprintf("%s:%s:nn=%d", name, affinity(ctype), notnull))
			if pk > 0 {
				pkCols = append(pkCols, name)
			}
		}
		require.NoError(t, crows.Err())
		crows.Close()
		sort.Strings(cols)
		sort.Strings(pkCols) // set comparison, not order
		fmt.Fprintf(&b, "TABLE %s COLS[%s] PK{%s}\n", tbl, strings.Join(cols, ","), strings.Join(pkCols, ","))

		// Indexes: name : unique : column-set. Skip sqlite auto-indexes
		// (implementation detail of PK/unique enforcement).
		irows, err := db.Query(fmt.Sprintf("PRAGMA index_list(%q)", tbl))
		require.NoError(t, err)
		type idx struct {
			name   string
			unique int
		}
		var idxs []idx
		for irows.Next() {
			var seq, unique, partial int
			var name, origin string
			require.NoError(t, irows.Scan(&seq, &name, &unique, &origin, &partial))
			idxs = append(idxs, idx{name, unique})
		}
		require.NoError(t, irows.Err())
		irows.Close()

		var idxLines []string
		for _, ix := range idxs {
			if strings.HasPrefix(ix.name, "sqlite_autoindex_") {
				continue
			}
			jrows, err := db.Query(fmt.Sprintf("PRAGMA index_info(%q)", ix.name))
			require.NoError(t, err)
			var cset []string
			for jrows.Next() {
				var seqno, cid int
				var cname sql.NullString
				require.NoError(t, jrows.Scan(&seqno, &cid, &cname))
				cset = append(cset, cname.String)
			}
			require.NoError(t, jrows.Err())
			jrows.Close()
			sort.Strings(cset)
			idxLines = append(idxLines, fmt.Sprintf("%s:u=%d:[%s]", ix.name, ix.unique, strings.Join(cset, ",")))
		}
		sort.Strings(idxLines)
		fmt.Fprintf(&b, "TABLE %s IDX[%s]\n", tbl, strings.Join(idxLines, ";"))
	}
	return b.String()
}

func TestSchemaParityV1V2SQLite(t *testing.T) {
	logV1, _ := test.NewNullLogger()
	logV2, _ := test.NewNullLogger()

	v1Path := filepath.ToSlash(filepath.Join(t.TempDir(), "v1.sqlite3"))
	v2Path := filepath.ToSlash(filepath.Join(t.TempDir(), "v2.sqlite3"))

	v1Schema := semanticSchema(t, v1.New(logV1), v1Path)
	v2Schema := semanticSchema(t, v2.New(logV2), v2Path)

	require.NotEmpty(t, v1Schema)
	require.Equal(t, v1Schema, v2Schema, "v2 sqlite schema must be semantically identical to v1")
}
