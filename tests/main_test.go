package main

import (
	"context"
	"testing"
	"time"

	license "github.com/CodeClarityCE/plugin-sca-license/src"
	"github.com/CodeClarityCE/utility-boilerplates/testdeps"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"
)

// knowledgeDB returns a throwaway knowledge database where ms is MIT licensed.
func knowledgeDB(tb testing.TB) *bun.DB {
	tb.Helper()
	db := testdeps.Postgres(tb)
	ctx := context.Background()
	_, err := db.ExecContext(ctx, `CREATE EXTENSION IF NOT EXISTS "uuid-ossp"`)
	require.NoError(tb, err)
	for _, model := range []any{(*knowledge.Package)(nil), (*knowledge.Version)(nil), (*knowledge.License)(nil)} {
		_, err = db.NewCreateTable().Model(model).Exec(ctx)
		require.NoError(tb, err)
	}
	_, err = db.ExecContext(ctx, `
		INSERT INTO package (name, language, license) VALUES ('ms', 'javascript', 'MIT');
		INSERT INTO licenses ("licenseId", name) VALUES ('MIT', 'MIT License');`)
	require.NoError(tb, err)
	return db
}

func TestCreate(t *testing.T) {
	db := knowledgeDB(t)
	licensePolicy := knowledge.LicensePolicy{DisallowedLicense: []string{"MIT"}}

	out, err := license.Start(db, getmockSBOM(), "JS", licensePolicy, time.Now())
	require.NoError(t, err)

	require.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	workspace := out.WorkSpaces["."]
	assert.Equal(t, []string{"ms@2.1.3"}, workspace.LicensesDepMap["MIT"])
	assert.Equal(t, []string{"MIT"}, workspace.LicenseComplianceViolations)
}

func BenchmarkCreate(b *testing.B) {
	db := knowledgeDB(b)
	licensePolicy := knowledge.LicensePolicy{DisallowedLicense: []string{"MIT"}}
	sbom := getmockSBOM()

	for b.Loop() {
		out, err := license.Start(db, sbom, "JS", licensePolicy, time.Now())
		if err != nil {
			b.Fatal(err)
		}
		assert.Equal(b, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	}
}
