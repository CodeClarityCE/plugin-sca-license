package matcher

import (
	"log"

	"slices"

	sbomTypes "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js"
	licenseRepository "github.com/CodeClarityCE/plugin-sca-license/src/repository/license"
	types "github.com/CodeClarityCE/plugin-sca-license/src/types"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

type LicenseDataSource string

const (
	LICENSE_DATA_SOURCE_SBOM LicenseDataSource = "LICENSE_DATA_SOURCE_SBOM"
	LICENSE_DATA_SOURCE_DB   LicenseDataSource = "LICENSE_DATA_SOURCE_DB"
)

type LicenseMatcher struct {
	PostProcessLicenses bool
	LicenseDataSource   LicenseDataSource
}

func (lm LicenseMatcher) GetWorkSpaceLicenses(knowledge_db *bun.DB, dependencies map[string]map[string]sbomTypes.Versions, licensePolicy knowledge.LicensePolicy) types.WorkSpaceLicenseInfoInternal {
	licensesDepMap := map[string][]string{}
	nonSpdxLicensesDepMap := map[string][]string{}
	licenseComplianceViolations := map[string][]string{}

	for dependency_name, dependency := range dependencies {
		for version_name := range dependency {
			key := dependency_name + "@" + version_name
			if lm.LicenseDataSource == LICENSE_DATA_SOURCE_DB {
				licenses, err := licenseRepository.GetDependencyLicenses(knowledge_db, dependency_name, version_name)
				if err != nil {
					log.Printf("Unable to retrieve linked licenses for package: %s", dependency_name)
					nonSpdxLicensesDepMap[""] = append(nonSpdxLicensesDepMap[""], key)
					continue
				}

				// Linked licenses are always spdx, verified during the knowledge base import
				for _, license := range licenses {
					deps := append(licensesDepMap[license.LicenseID], key)
					licensesDepMap[license.LicenseID] = deps

					if slices.Contains(licensePolicy.DisallowedLicense, license.LicenseID) {
						deps := append(licenseComplianceViolations[license.LicenseID], key)
						licenseComplianceViolations[license.LicenseID] = deps
					}
				}

			}
			// else if lm.LicenseDataSource == LICENSE_DATA_SOURCE_SBOM {
			// 	// TODO implement
			// }
		}

	}

	workSpaceLicenseInfo := types.WorkSpaceLicenseInfoInternal{
		LicensesDepMap:              licensesDepMap,
		NonSpdxLicensesDepMap:       nonSpdxLicensesDepMap,
		LicenseComplianceViolations: licenseComplianceViolations,
	}

	return workSpaceLicenseInfo

}
