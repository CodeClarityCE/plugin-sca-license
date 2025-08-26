package main

import (
	"os"
	"testing"
	"time"

	license "github.com/CodeClarityCE/plugin-sca-license/src"
	"github.com/CodeClarityCE/utility-boilerplates"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/stretchr/testify/assert"
)

func TestCreate(t *testing.T) {
	// Set test database environment
	os.Setenv("PG_DB_HOST", "127.0.0.1")
	os.Setenv("PG_DB_PORT", "5432")
	os.Setenv("PG_DB_USER", "postgres")
	os.Setenv("PG_DB_PASSWORD", "!ChangeMe!")

	// Create PluginBase for testing
	pluginBase, err := boilerplates.CreatePluginBase()
	if err != nil {
		t.Skipf("Skipping test due to database connection error: %v", err)
		return
	}
	defer pluginBase.Close()

	var licensePolicy = knowledge.LicensePolicy{}
	licensePolicy.DisallowedLicense = []string{"MIT"}

	sbom := getmockSBOM()

	out := license.Start(pluginBase.DB.Knowledge, sbom, "JS", licensePolicy, time.Now())

	// Assert the expected values
	assert.NotNil(t, out)
	assert.Equal(t, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	assert.NotEmpty(t, out.WorkSpaces)
}

func BenchmarkCreate(b *testing.B) {
	// Set test database environment
	os.Setenv("PG_DB_HOST", "127.0.0.1")
	os.Setenv("PG_DB_PORT", "5432")
	os.Setenv("PG_DB_USER", "postgres")
	os.Setenv("PG_DB_PASSWORD", "!ChangeMe!")

	// Create PluginBase for testing
	pluginBase, err := boilerplates.CreatePluginBase()
	if err != nil {
		b.Skipf("Skipping benchmark due to database connection error: %v", err)
		return
	}
	defer pluginBase.Close()

	var licensePolicy = knowledge.LicensePolicy{}
	licensePolicy.DisallowedLicense = []string{"MIT"}

	sbom := getmockSBOM()

	out := license.Start(pluginBase.DB.Knowledge, sbom, "JS", licensePolicy, time.Now())

	// Assert the expected values
	assert.NotNil(b, out)
	assert.Equal(b, codeclarity.SUCCESS, out.AnalysisInfo.Status)
	assert.NotEmpty(b, out.WorkSpaces)
}
