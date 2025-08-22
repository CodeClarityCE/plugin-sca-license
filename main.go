package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	sbom "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js"
	plugin "github.com/CodeClarityCE/plugin-sca-license/src"
	"github.com/CodeClarityCE/plugin-sca-license/src/outputGenerator"
	"github.com/CodeClarityCE/plugin-sca-license/src/types"
	"github.com/CodeClarityCE/utility-types/boilerplates"
	types_amqp "github.com/CodeClarityCE/utility-types/amqp"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	"github.com/CodeClarityCE/utility-types/exceptions"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	exceptionManager "github.com/CodeClarityCE/utility-types/exceptions"
	plugin_db "github.com/CodeClarityCE/utility-types/plugin_db"
	"github.com/google/uuid"
)

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
		for _, license := range messageData["licensePolicy"].([]interface{}) {
			licensePolicy.DisallowedLicense = append(licensePolicy.DisallowedLicense, license.(string))
		}
	}

	// Get previous stage
	analysis_stage := analysis_document.Stage - 1
	// Get all SBOM keys from previous stage
	sbomKeys := []struct {
		id         uuid.UUID
		language   string
		pluginName string
	}{}

	for _, step := range analysis_document.Steps[analysis_stage] {
		if step.Name == "js-sbom" {
			sbomKeyUUID, err := uuid.Parse(step.Result["sbomKey"].(string))
			if err != nil {
				panic(err)
			}
			sbomKeys = append(sbomKeys, struct {
				id         uuid.UUID
				language   string
				pluginName string
			}{sbomKeyUUID, "JS", "js-sbom"})
		} else if step.Name == "php-sbom" {
			sbomKeyUUID, err := uuid.Parse(step.Result["sbomKey"].(string))
			if err != nil {
				panic(err)
			}
			sbomKeys = append(sbomKeys, struct {
				id         uuid.UUID
				language   string
				pluginName string
			}{sbomKeyUUID, "PHP", "php-sbom"})
		}
	}

	var licenseOutput types.Output
	var err error
	start := time.Now()

	// If no SBOMs were found, return success with empty results
	if len(sbomKeys) == 0 {
		licenseOutput = outputGenerator.SuccessOutput(map[string]types.WorkSpaceLicenseInfo{}, types.AnalysisStats{}, sbom.AnalysisInfo{
			Status: codeclarity.SUCCESS,
		}, start)
	} else {
		// Process ALL available SBOMs and merge their results
		mergedWorkspaces := make(map[string]types.WorkSpaceLicenseInfo)
		mergedStats := types.AnalysisStats{}
		hasErrors := false

		for _, sbomInfo := range sbomKeys {
			log.Printf("Processing %s SBOM for license analysis", sbomInfo.language)

			res := codeclarity.Result{
				Id: sbomInfo.id,
			}
			err = databases.Codeclarity.NewSelect().Model(&res).Where("id = ?", sbomInfo.id).Scan(context.Background())
			if err != nil {
				log.Printf("Failed to retrieve %s SBOM: %v", sbomInfo.language, err)
				continue
			}

			sbomData := sbom.Output{}
			err = json.Unmarshal(res.Result.([]byte), &sbomData)
			if err != nil {
				log.Printf("Failed to unmarshal %s SBOM: %v", sbomInfo.language, err)
				exceptionManager.AddError(
					"", exceptions.GENERIC_ERROR,
					fmt.Sprintf("Error when reading %s output: %s", sbomInfo.pluginName, err), exceptions.FAILED_TO_READ_PREVIOUS_STAGE_OUTPUT,
				)
				hasErrors = true
				continue
			}

			// Process this SBOM
			individualOutput := plugin.Start(databases.Knowledge, sbomData, sbomInfo.language, licensePolicy, start)
			
			if individualOutput.AnalysisInfo.Status != codeclarity.SUCCESS {
				log.Printf("%s license analysis failed", sbomInfo.language)
				hasErrors = true
				continue
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
					for depKey, depInfo := range workspaceData.DependencyInfo {
						existing.DependencyInfo[depKey] = depInfo
					}

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

			// Individual output processed successfully - stats already merged above
		}

		if hasErrors && len(mergedWorkspaces) == 0 {
			// If all SBOM processing failed, return failure
			sbomAnalysisInfo := sbom.AnalysisInfo{Status: codeclarity.FAILURE}
			licenseOutput = outputGenerator.FailureOutput(sbomAnalysisInfo, start)
		} else {
			// Return merged results with empty sbom.AnalysisInfo for compatibility
			sbomAnalysisInfo := sbom.AnalysisInfo{Status: codeclarity.SUCCESS}
			
			log.Printf("License analysis completed: merged %d workspaces from %d SBOMs", len(mergedWorkspaces), len(sbomKeys))
			licenseOutput = outputGenerator.SuccessOutput(mergedWorkspaces, mergedStats, sbomAnalysisInfo, start)
		}
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
