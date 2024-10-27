package main

import (
	"database/sql"
	"os"
	"testing"
	"time"

	license "github.com/CodeClarityCE/plugin-sca-license/src"
	dbhelper "github.com/CodeClarityCE/utility-dbhelper/helper"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/stretchr/testify/assert"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"
)

func TestCreate(t *testing.T) {
	os.Setenv("PG_DB_HOST", "127.0.0.1")
	os.Setenv("PG_DB_PORT", "5432")
	os.Setenv("PG_DB_USER", "postgres")
	os.Setenv("PG_DB_PASSWORD", "!ChangeMe!")

	dsn_knowledge := "postgres://postgres:!ChangeMe!@127.0.0.1:5432/" + dbhelper.Config.Database.Knowledge + "?sslmode=disable"
	sqldb_knowledge := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn_knowledge)))
	db_knowledge := bun.NewDB(sqldb_knowledge, pgdialect.New())
	defer db_knowledge.Close()

	var licensePolicy = knowledge.LicensePolicy{}
	licensePolicy.DisallowedLicense = []string{"MIT"}

	sbom := getmockSBOM()

	out := license.Start(db_knowledge, sbom, "JS", licensePolicy, time.Now())

	// Assert the expected values
	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	assert.NotEmpty(t, out.WorkSpaces)
}

func BenchmarkCreate(b *testing.B) {
	os.Setenv("PG_DB_HOST", "127.0.0.1")
	os.Setenv("PG_DB_PORT", "5432")
	os.Setenv("PG_DB_USER", "postgres")
	os.Setenv("PG_DB_PASSWORD", "!ChangeMe!")

	dsn_knowledge := "postgres://postgres:!ChangeMe!@127.0.0.1:5432/" + dbhelper.Config.Database.Knowledge + "?sslmode=disable"
	sqldb_knowledge := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn_knowledge)))
	db_knowledge := bun.NewDB(sqldb_knowledge, pgdialect.New())
	defer db_knowledge.Close()

	var licensePolicy = knowledge.LicensePolicy{}
	licensePolicy.DisallowedLicense = []string{"MIT"}

	sbom := getmockSBOM()

	out := license.Start(db_knowledge, sbom, "JS", licensePolicy, time.Now())

	// Assert the expected values
	assert.NotNil(b, out)
	assert.Equal(b, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	assert.NotEmpty(b, out.WorkSpaces)
}
