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

// Knowledge answers the license questions the matcher asks of the knowledge base.
type Knowledge interface {
	PackageLicense(name string) (string, error)
	IsSpdxLicense(id string) bool
}

type dbKnowledge struct{ db *bun.DB }

func (k dbKnowledge) PackageLicense(name string) (string, error) {
	return licenseRepository.GetPackageLicense(k.db, name)
}

func (k dbKnowledge) IsSpdxLicense(id string) bool {
	_, err := licenseRepository.GetSPDXLicenseByName(id, k.db)
	return err == nil
}

func (lm LicenseMatcher) GetWorkSpaceLicenses(knowledge_db *bun.DB, dependencies map[string]map[string]sbomTypes.Versions, licensePolicy knowledge.LicensePolicy) types.WorkSpaceLicenseInfoInternal {
	return lm.MatchWorkSpaceLicenses(dbKnowledge{db: knowledge_db}, dependencies, licensePolicy)
}

// MatchWorkSpaceLicenses lists each dependency under every license its license expression names.
func (lm LicenseMatcher) MatchWorkSpaceLicenses(source Knowledge, dependencies map[string]map[string]sbomTypes.Versions, licensePolicy knowledge.LicensePolicy) types.WorkSpaceLicenseInfoInternal {
	licensesDepMap := map[string][]string{}
	nonSpdxLicensesDepMap := map[string][]string{}
	licenseComplianceViolations := map[string][]string{}

	for dependency_name, dependency := range dependencies {
		for version_name := range dependency {
			key := dependency_name + "@" + version_name
			if lm.LicenseDataSource != LICENSE_DATA_SOURCE_DB {
				continue
			}
			expression, err := source.PackageLicense(dependency_name)
			ids := LicenseIDs(expression)
			if err != nil || len(ids) == 0 {
				log.Printf("Unable to retrieve linked licenses for package: %s", dependency_name)
				nonSpdxLicensesDepMap[""] = append(nonSpdxLicensesDepMap[""], key)
				continue
			}

			for _, id := range ids {
				if !source.IsSpdxLicense(id) {
					nonSpdxLicensesDepMap[id] = append(nonSpdxLicensesDepMap[id], key)
					continue
				}
				licensesDepMap[id] = append(licensesDepMap[id], key)
				if slices.Contains(licensePolicy.DisallowedLicense, id) {
					licenseComplianceViolations[id] = append(licenseComplianceViolations[id], key)
				}
			}
		}
	}

	return types.WorkSpaceLicenseInfoInternal{
		LicensesDepMap:              licensesDepMap,
		NonSpdxLicensesDepMap:       nonSpdxLicensesDepMap,
		LicenseComplianceViolations: licenseComplianceViolations,
	}
}
