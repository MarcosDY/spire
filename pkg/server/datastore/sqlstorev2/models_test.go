package sqlstorev2

import (
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestUintFieldsAreSize31 requires every uint model field to be tagged
// size:31. Without the tag the PostgreSQL driver creates bigint instead of
// v1's integer, which only the external-database parity test would catch.
func TestUintFieldsAreSize31(t *testing.T) {
	var check func(typ reflect.Type)
	check = func(typ reflect.Type) {
		for field := range typ.Fields() {
			switch {
			case field.Anonymous:
				check(field.Type)
			case field.Type.Kind() == reflect.Uint:
				require.Contains(t, strings.Split(field.Tag.Get("gorm"), ";"), "size:31",
					"%s.%s must be tagged size:31", typ.Name(), field.Name)
			}
		}
	}
	for _, model := range []any{
		Bundle{}, AttestedNode{}, AttestedNodeEvent{}, NodeSelector{},
		RegisteredEntry{}, RegisteredEntryEvent{}, JoinToken{}, Selector{},
		Migration{}, DNSName{}, FederatedTrustDomain{}, CAJournal{},
		FederatedRegistrationEntry{},
	} {
		check(reflect.TypeOf(model))
	}
}
