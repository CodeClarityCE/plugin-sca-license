package license

import (
	"maps"
	"time"

	sbom "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js"
	licenseMatcherManager "github.com/CodeClarityCE/plugin-sca-license/src/licenseMatcher"
	outputGenerator "github.com/CodeClarityCE/plugin-sca-license/src/outputGenerator"
	types "github.com/CodeClarityCE/plugin-sca-license/src/types"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	exceptionManager "github.com/CodeClarityCE/utility-types/exceptions"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

// knowledgeLanguages maps an SBOM language to the language its packages have in the knowledge base.
var knowledgeLanguages = map[string]string{"JS": "javascript", "PHP": "php"}

// Start is a function that starts the analysis process for a given SBOM (Software Bill of Materials).
// It takes the SBOM ID, language ID, license policy, and database as input parameters.
// It returns the analysis output as a types.Output struct.
// A failed knowledge lookup returns a failed output and an ErrKnowledgeLookup error.
func Start(knowledge_db *bun.DB, sbom sbom.Output, languageId string, licensePolicy knowledge.LicensePolicy, start time.Time) (types.Output, error) {
	return StartWithKnowledge(licenseMatcherManager.DBKnowledge(knowledge_db), sbom, languageId, licensePolicy, start)
}

// StartWithKnowledge is Start with the knowledge lookups supplied.
func StartWithKnowledge(source licenseMatcherManager.Knowledge, sbom sbom.Output, languageId string, licensePolicy knowledge.LicensePolicy, start time.Time) (types.Output, error) {

	// Check if the previous stage finished correctly
	if sbom.AnalysisInfo.Status != codeclarity.SUCCESS {
		exceptionManager.AddError(
			"Execution of the previous stage was unsuccessful, upon which the current stage relies", exceptionManager.PREVIOUS_STAGE_FAILED,
			"Execution of the previous stage was unsuccessful, upon which the current stage relies", exceptionManager.PREVIOUS_STAGE_FAILED,
		)

		return outputGenerator.FailureOutput(sbom.AnalysisInfo, start), nil
	}

	var licenseMatcher licenseMatcherManager.LicenseMatcher

	language_supported := false
	// Check which language was requested
	if knowledgeLanguage, ok := knowledgeLanguages[languageId]; ok {
		licenseMatcher = licenseMatcherManager.LicenseMatcher{
			LicenseDataSource:   licenseMatcherManager.LICENSE_DATA_SOURCE_DB,
			PostProcessLicenses: true,
			Language:            knowledgeLanguage,
		}
		language_supported = true
	}

	// In case language is not supported return an error
	if !language_supported {
		exceptionManager.AddError("", exceptionManager.UNSUPPORTED_LANGUAGE_REQUESTED, "", exceptionManager.UNSUPPORTED_LANGUAGE_REQUESTED)
		return outputGenerator.FailureOutput(sbom.AnalysisInfo, start), nil
	}

	workSpaceData := map[string]types.WorkSpaceLicenseInfoInternal{}

	// workSpaceData := map[string]types.WorkSpaceVulnerabilitiesInternal{}
	for workspaceKey, workspace := range sbom.WorkSpaces {
		info, err := licenseMatcher.MatchWorkSpaceLicenses(source, workspace.Dependencies, licensePolicy)
		if err != nil {
			return outputGenerator.FailureOutput(sbom.AnalysisInfo, start), err
		}
		workSpaceData[workspaceKey] = info
	}

	// Generate truncated workspace data for the output
	workSpaceDataTruncated := map[string]types.WorkSpaceLicenseInfo{}

	for workSpaceKey, workSpaceLicenseInfoInternal := range workSpaceData {
		workSpaceLicenseInfo := types.WorkSpaceLicenseInfo{
			LicensesDepMap:              map[string][]string{},
			NonSpdxLicensesDepMap:       map[string][]string{},
			LicenseComplianceViolations: []string{},
			DependencyInfo:              workSpaceLicenseInfoInternal.DependencyInfo,
		}

		for licenseKey, depsUsingLicense := range workSpaceLicenseInfoInternal.LicensesDepMap {
			workSpaceLicenseInfo.LicensesDepMap[licenseKey] = append(workSpaceLicenseInfo.LicensesDepMap[licenseKey], depsUsingLicense...)
		}

		maps.Copy(workSpaceLicenseInfo.NonSpdxLicensesDepMap, workSpaceLicenseInfoInternal.NonSpdxLicensesDepMap)

		for licenseKey := range workSpaceLicenseInfoInternal.LicenseComplianceViolations {
			workSpaceLicenseInfo.LicenseComplianceViolations = append(workSpaceLicenseInfo.LicenseComplianceViolations, licenseKey)
		}

		workSpaceDataTruncated[workSpaceKey] = workSpaceLicenseInfo
	}

	// Generate license stats
	analysisStats := outputGenerator.GenerateAnalysisStats(workSpaceData)

	// Return the analysis results
	return outputGenerator.SuccessOutput(workSpaceDataTruncated, analysisStats, sbom.AnalysisInfo, start), nil
}
