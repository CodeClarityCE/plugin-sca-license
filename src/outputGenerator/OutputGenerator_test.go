package outputGenerator

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sbomTypes "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js"
	"github.com/CodeClarityCE/plugin-sca-license/src/types"
)

func storedLicenseDist(t *testing.T, stats types.AnalysisStats) string {
	t.Helper()
	encoded, err := json.Marshal(stats)
	require.NoError(t, err)
	var fields map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(encoded, &fields))
	return string(fields["license_dist"])
}

func TestEmptySuccessStoresAnEmptyLicenseDistribution(t *testing.T) {
	output := SuccessOutput(map[string]types.WorkSpaceLicenseInfo{}, types.AnalysisStats{}, sbomTypes.AnalysisInfo{}, time.Now())

	assert.Equal(t, "{}", storedLicenseDist(t, output.AnalysisInfo.AnalysisStats))
}

func TestFailureStoresAnEmptyLicenseDistribution(t *testing.T) {
	output := FailureOutput(sbomTypes.AnalysisInfo{}, time.Now())

	assert.Equal(t, "{}", storedLicenseDist(t, output.AnalysisInfo.AnalysisStats))
}
