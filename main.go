package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"maps"
	"time"

	sbom "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js"
	plugin "github.com/CodeClarityCE/plugin-sca-license/src"
	"github.com/CodeClarityCE/plugin-sca-license/src/outputGenerator"
	"github.com/CodeClarityCE/plugin-sca-license/src/types"
	"github.com/CodeClarityCE/utility-boilerplates"
	types_amqp "github.com/CodeClarityCE/utility-types/amqp"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	"github.com/CodeClarityCE/utility-types/exceptions"
	exceptionManager "github.com/CodeClarityCE/utility-types/exceptions"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	plugin_db "github.com/CodeClarityCE/utility-types/plugin_db"
	"github.com/google/uuid"
)

// sbomKey identifies one SBOM result to process.
type sbomKey struct {
	id         uuid.UUID
	language   string
	pluginName string
}

// sbomKeysFromSteps returns the SBOM results of the steps that ran across the given stages.
func sbomKeysFromSteps(stages [][]codeclarity.Step) []sbomKey {
	languages := map[string]string{"js-sbom": "JS", "php-sbom": "PHP"}
	keys := []sbomKey{}
	for _, steps := range stages {
		for _, step := range steps {
			language, isSbom := languages[step.Name]
			if !isSbom || step.Status != codeclarity.SUCCESS {
				continue
			}
			id, err := uuid.Parse(step.Result["sbomKey"].(string))
			if err != nil {
				panic(err)
			}
			keys = append(keys, sbomKey{id, language, step.Name})
		}
	}
	return keys
}

// LicenseAnalysisHandler implements the AnalysisHandler interface
type LicenseAnalysisHandler struct{}

// StartAnalysis implements the AnalysisHandler interface
func (h *LicenseAnalysisHandler) StartAnalysis(
	databases *boilerplates.PluginDatabases,
	dispatcherMessage types_amqp.DispatcherPluginMessage,
	config plugin_db.Plugin,
	analysisDoc codeclarity.Analysis,
) (map[string]any, codeclarity.AnalysisStatus, error) {
	return startAnalysis(databases, dispatcherMessage, config, analysisDoc)
}

// main is the entry point of the program.
func main() {
	pluginBase, err := boilerplates.CreatePluginBase()
	if err != nil {
		log.Fatalf("Failed to initialize plugin base: %v", err)
	}
	defer pluginBase.Close()

	// Start the plugin with our analysis handler
	handler := &LicenseAnalysisHandler{}
	err = pluginBase.Listen(handler)
	if err != nil {
		log.Fatalf("Failed to start plugin: %v", err)
	}
}

func startAnalysis(databases *boilerplates.PluginDatabases, dispatcherMessage types_amqp.DispatcherPluginMessage, config plugin_db.Plugin, analysis_document codeclarity.Analysis) (map[string]any, codeclarity.AnalysisStatus, error) {
	// Get analysis config
	messageData := analysis_document.Config[config.Name].(map[string]any)
	// Prepare the arguments for the plugin
	licensePolicy := knowledge.LicensePolicy{}
	if messageData["licensePolicy"] != nil {
		for _, license := range messageData["licensePolicy"].([]any) {
			licensePolicy.DisallowedLicense = append(licensePolicy.DisallowedLicense, license.(string))
		}
	}

	// Get all SBOM keys from every earlier stage
	earlierStages := analysis_document.Steps[:min(analysis_document.Stage, len(analysis_document.Steps))]
	sbomKeys := sbomKeysFromSteps(earlierStages)

	var licenseOutput types.Output
	var err error
	start := time.Now()

	// If no SBOMs were found, return success with empty results
	if len(sbomKeys) == 0 {
		licenseOutput = outputGenerator.SuccessOutput(map[string]types.WorkSpaceLicenseInfo{}, types.AnalysisStats{}, sbom.AnalysisInfo{
			Status: codeclarity.SUCCESS,
		}, start)
	} else {
		licenseOutput = combineLicenseOutputs(sbomKeys, func(sbomInfo sbomKey) (types.Output, error) {
			return analyzeSbom(databases, sbomInfo, licensePolicy, start)
		}, start)
	}

	license_result := codeclarity.Result{
		Result:     types.ConvertOutputToMap(licenseOutput),
		AnalysisId: dispatcherMessage.AnalysisId,
		Plugin:     config.Name,
		CreatedOn:  time.Now(),
	}
	_, err = databases.Codeclarity.NewInsert().Model(&license_result).Exec(context.Background())
	if err != nil {
		panic(err)
	}

	// Prepare the result to store in step
	// In this case we only store the sbomKey
	// The other plugins will use this key to get the sbom
	result := make(map[string]any)
	result["licenseKey"] = license_result.Id

	// The output is always a map[string]any
	return result, licenseOutput.AnalysisInfo.Status, nil
}

// analyzeSbom loads one stored SBOM and runs the license analysis on it.
func analyzeSbom(databases *boilerplates.PluginDatabases, sbomInfo sbomKey, licensePolicy knowledge.LicensePolicy, start time.Time) (types.Output, error) {
	log.Printf("Processing %s SBOM for license analysis", sbomInfo.language)

	res := codeclarity.Result{Id: sbomInfo.id}
	err := databases.Codeclarity.NewSelect().Model(&res).Where("id = ?", sbomInfo.id).Scan(context.Background())
	if err != nil {
		return types.Output{}, fmt.Errorf("retrieve %s SBOM: %w", sbomInfo.language, err)
	}
	raw, ok := res.Result.([]byte)
	if !ok {
		return types.Output{}, fmt.Errorf("%s SBOM is not stored as bytes", sbomInfo.language)
	}

	sbomData := sbom.Output{}
	if err = json.Unmarshal(raw, &sbomData); err != nil {
		exceptionManager.AddError(
			"", exceptions.GENERIC_ERROR,
			fmt.Sprintf("Error when reading %s output: %s", sbomInfo.pluginName, err), exceptions.FAILED_TO_READ_PREVIOUS_STAGE_OUTPUT,
		)
		return types.Output{}, fmt.Errorf("unmarshal %s SBOM: %w", sbomInfo.language, err)
	}
	return plugin.Start(databases.Knowledge, sbomData, sbomInfo.language, licensePolicy, start), nil
}

// combineLicenseOutputs merges the license results of every SBOM.
// One SBOM that cannot be analyzed fails the step, so no ecosystem goes missing.
func combineLicenseOutputs(sbomKeys []sbomKey, analyze func(sbomKey) (types.Output, error), start time.Time) types.Output {
	failed := func() types.Output {
		return outputGenerator.FailureOutput(sbom.AnalysisInfo{Status: codeclarity.FAILURE}, start)
	}
	mergedWorkspaces := make(map[string]types.WorkSpaceLicenseInfo)
	mergedStats := types.AnalysisStats{}

	for _, sbomInfo := range sbomKeys {
		individualOutput, err := analyze(sbomInfo)
		if err != nil {
			log.Printf("License analysis failed: %v", err)
			return failed()
		}
		if individualOutput.AnalysisInfo.Status != codeclarity.SUCCESS {
			log.Printf("%s license analysis failed", sbomInfo.language)
			return failed()
		}

		log.Printf("Successfully processed %s license analysis with %d workspaces", sbomInfo.language, len(individualOutput.WorkSpaces))

		// Merge the workspaces from this SBOM into the combined result
		for workspaceKey, workspaceData := range individualOutput.WorkSpaces {
			if existing, exists := mergedWorkspaces[workspaceKey]; exists {
				// Merge license data for existing workspace
				for licenseId, deps := range workspaceData.LicensesDepMap {
					if existingDeps, existsLicense := existing.LicensesDepMap[licenseId]; existsLicense {
						// Combine dependencies, avoiding duplicates
						combined := make(map[string]bool)
						for _, dep := range existingDeps {
							combined[dep] = true
						}
						for _, dep := range deps {
							combined[dep] = true
						}

						var mergedDeps []string
						for dep := range combined {
							mergedDeps = append(mergedDeps, dep)
						}
						existing.LicensesDepMap[licenseId] = mergedDeps
					} else {
						existing.LicensesDepMap[licenseId] = deps
					}
				}

				// Merge non-SPDX license data
				for licenseId, deps := range workspaceData.NonSpdxLicensesDepMap {
					if existingDeps, existsLicense := existing.NonSpdxLicensesDepMap[licenseId]; existsLicense {
						// Combine dependencies, avoiding duplicates
						combined := make(map[string]bool)
						for _, dep := range existingDeps {
							combined[dep] = true
						}
						for _, dep := range deps {
							combined[dep] = true
						}

						var mergedDeps []string
						for dep := range combined {
							mergedDeps = append(mergedDeps, dep)
						}
						existing.NonSpdxLicensesDepMap[licenseId] = mergedDeps
					} else {
						existing.NonSpdxLicensesDepMap[licenseId] = deps
					}
				}

				// Merge license compliance violations (avoiding duplicates)
				violationSet := make(map[string]bool)
				for _, violation := range existing.LicenseComplianceViolations {
					violationSet[violation] = true
				}
				for _, violation := range workspaceData.LicenseComplianceViolations {
					violationSet[violation] = true
				}

				var mergedViolations []string
				for violation := range violationSet {
					mergedViolations = append(mergedViolations, violation)
				}
				existing.LicenseComplianceViolations = mergedViolations

				// Merge dependency info
				maps.Copy(existing.DependencyInfo, workspaceData.DependencyInfo)

				mergedWorkspaces[workspaceKey] = existing
			} else {
				// New workspace, add it directly
				mergedWorkspaces[workspaceKey] = workspaceData
			}
		}

		// Merge analysis statistics
		mergedStats.NumberOfSpdxLicenses += individualOutput.AnalysisInfo.AnalysisStats.NumberOfSpdxLicenses
		mergedStats.NumberOfNonSpdxLicenses += individualOutput.AnalysisInfo.AnalysisStats.NumberOfNonSpdxLicenses
		mergedStats.NumberOfCopyLeftLicenses += individualOutput.AnalysisInfo.AnalysisStats.NumberOfCopyLeftLicenses
		mergedStats.NumberOfPermissiveLicenses += individualOutput.AnalysisInfo.AnalysisStats.NumberOfPermissiveLicenses

		// Merge license distribution maps
		for licenseType, count := range individualOutput.AnalysisInfo.AnalysisStats.LicenseDist {
			if mergedStats.LicenseDist == nil {
				mergedStats.LicenseDist = make(map[string]int)
			}
			mergedStats.LicenseDist[licenseType] += count
		}
	}

	log.Printf("License analysis completed: merged %d workspaces from %d SBOMs", len(mergedWorkspaces), len(sbomKeys))
	return outputGenerator.SuccessOutput(mergedWorkspaces, mergedStats, sbom.AnalysisInfo{Status: codeclarity.SUCCESS}, start)
}
