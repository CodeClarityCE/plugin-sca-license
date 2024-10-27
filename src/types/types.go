package types

import (
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	exceptions "github.com/CodeClarityCE/utility-types/exceptions"
)

type WorkSpaceLicenseInfo struct {
	LicensesDepMap              map[string][]string
	NonSpdxLicensesDepMap       map[string][]string
	LicenseComplianceViolations []string
	DependencyInfo              map[string]DependencyInfo
}

type AnalysisStatus string

const (
	SUCCESS AnalysisStatus = "success"
	FAILURE AnalysisStatus = "failure"
)

type DependencyInfo struct {
	Licenses        []string
	NonSpdxLicenses []string
}

type WorkSpaceLicenseInfoInternal struct {
	LicensesDepMap              map[string][]string
	NonSpdxLicensesDepMap       map[string][]string
	LicenseComplianceViolations map[string][]string
	DependencyInfo              map[string]DependencyInfo
}

type AnalysisStats struct {
	NumberOfSpdxLicenses       int                             `json:"number_of_spdx_licenses"`
	NumberOfNonSpdxLicenses    int                             `json:"number_of_non_spdx_licenses"`
	NumberOfCopyLeftLicenses   int                             `json:"number_of_copy_left_licenses"`
	NumberOfPermissiveLicenses int                             `json:"number_of_permissive_licenses"`
	LicenseDist                AnalysisStatLicenseSeverityDist `json:"license_dist"`
}

type AnalysisInfo struct {
	Status                   codeclarity.AnalysisStatus `json:"status"`
	Errors                   []exceptions.Error         `json:"errors"`
	AnalysisStartTime        string                     `json:"analysis_start_time"`
	AnalysisEndTime          string                     `json:"analysis_end_time"`
	AnalysisDeltaTime        float64                    `json:"analysis_delta_time"`
	VersionSeperator         string                     `json:"version_seperator"`
	ImportPathSeperator      string                     `json:"import_path_seperator"`
	DefaultWorkspaceName     string                     `json:"default_workspace_name"`
	SelfManagedWorkspaceName string                     `json:"self_managed_workspace_name"`
	AnalysisStats            AnalysisStats              `json:"stats"`
}

type Output struct {
	WorkSpaces   map[string]WorkSpaceLicenseInfo `json:"workspaces"`
	AnalysisInfo AnalysisInfo                    `json:"analysis_info"`
}

type AnalysisStatLicenseSeverityDist map[string]int

func ConvertOutputToMap(output Output) map[string]interface{} {
	result := make(map[string]interface{})

	// Convert WorkSpaces to map
	workspaces := make(map[string]interface{})
	for key, value := range output.WorkSpaces {
		workspace := make(map[string]interface{})
		workspace["LicensesDepMap"] = value.LicensesDepMap
		workspace["NonSpdxLicensesDepMap"] = value.NonSpdxLicensesDepMap
		workspace["LicenseComplianceViolations"] = value.LicenseComplianceViolations
		workspace["DependencyInfo"] = value.DependencyInfo
		workspaces[key] = workspace
	}
	result["workspaces"] = workspaces

	// Convert AnalysisInfo to map
	analysisInfo := make(map[string]interface{})
	analysisInfo["status"] = output.AnalysisInfo.Status
	analysisInfo["errors"] = output.AnalysisInfo.Errors
	analysisInfo["analysis_start_time"] = output.AnalysisInfo.AnalysisStartTime
	analysisInfo["analysis_end_time"] = output.AnalysisInfo.AnalysisEndTime
	analysisInfo["analysis_delta_time"] = output.AnalysisInfo.AnalysisDeltaTime
	analysisInfo["version_seperator"] = output.AnalysisInfo.VersionSeperator
	analysisInfo["import_path_seperator"] = output.AnalysisInfo.ImportPathSeperator
	analysisInfo["default_workspace_name"] = output.AnalysisInfo.DefaultWorkspaceName
	analysisInfo["self_managed_workspace_name"] = output.AnalysisInfo.SelfManagedWorkspaceName
	analysisInfo["stats"] = output.AnalysisInfo.AnalysisStats
	result["analysis_info"] = analysisInfo

	return result
}
