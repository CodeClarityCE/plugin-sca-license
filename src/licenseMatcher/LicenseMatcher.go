package matcher

import (
	"database/sql"
	"errors"
	"fmt"
	"slices"

	sbomTypes "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js"
	licenseRepository "github.com/CodeClarityCE/plugin-sca-license/src/repository/license"
	types "github.com/CodeClarityCE/plugin-sca-license/src/types"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/sirupsen/logrus"
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
	// Language is the knowledge base language of the dependencies, such as "javascript" or "php".
	Language string
}

// ErrKnowledgeLookup marks a failed knowledge database lookup that fails the step.
var ErrKnowledgeLookup = errors.New("knowledge lookup failed")

// LicenseSource answers the license questions the matcher asks of the knowledge base.
// Something missing from the knowledge base is not an error.
type LicenseSource interface {
	// PackageLicense returns the licenses recorded for a package version, or found false if the package is unknown.
	PackageLicense(name, version, language string) (licenses PackageLicenses, found bool, err error)
	// IsSpdxLicense reports whether id is on the SPDX license list.
	IsSpdxLicense(id string) (bool, error)
}

// PackageLicenses holds the license expressions the knowledge base records for a package version.
type PackageLicenses struct {
	// Version is the license of the version asked about, empty when its row has none.
	Version string
	// Package is the package-level license, which is the newest release's.
	Package string
}

// Expression is the version's license, or the package's when the version has none.
func (l PackageLicenses) Expression() string {
	if l.Version != "" {
		return l.Version
	}
	return l.Package
}

type dbKnowledge struct{ db *bun.DB }

func (k dbKnowledge) PackageLicense(name, version, language string) (PackageLicenses, bool, error) {
	pkg, ver, err := licenseRepository.GetPackageLicense(k.db, name, version, language)
	if errors.Is(err, sql.ErrNoRows) {
		return PackageLicenses{}, false, nil
	}
	return PackageLicenses{Version: ver, Package: pkg}, err == nil, err
}

func (k dbKnowledge) IsSpdxLicense(id string) (bool, error) {
	_, err := licenseRepository.GetSPDXLicenseByName(id, k.db)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// DBKnowledge reads licenses from the knowledge database.
func DBKnowledge(knowledge_db *bun.DB) LicenseSource {
	return dbKnowledge{db: knowledge_db}
}

// MatchWorkSpaceLicenses lists each dependency under every license its license expression names.
// It stops at the first failed lookup and returns an ErrKnowledgeLookup error.
func (lm LicenseMatcher) MatchWorkSpaceLicenses(source LicenseSource, dependencies map[string]map[string]sbomTypes.Versions, licensePolicy knowledge.LicensePolicy) (types.WorkSpaceLicenseInfoInternal, error) {
	licensesDepMap := map[string][]string{}
	nonSpdxLicensesDepMap := map[string][]string{}
	licenseComplianceViolations := map[string][]string{}

	for dependency_name, dependency := range dependencies {
		for version_name := range dependency {
			key := dependency_name + "@" + version_name
			if lm.LicenseDataSource != LICENSE_DATA_SOURCE_DB {
				continue
			}
			licenses, found, err := source.PackageLicense(dependency_name, version_name, lm.Language)
			if err != nil {
				return types.WorkSpaceLicenseInfoInternal{}, fmt.Errorf("%w: license of %s: %w", ErrKnowledgeLookup, dependency_name, err)
			}
			expression := licenses.Expression()
			ids := LicenseIDs(expression)
			if !found || len(ids) == 0 {
				logrus.WithFields(logrus.Fields{"package": dependency_name, "version": version_name}).
					Warn("Unable to retrieve linked licenses for package")
				nonSpdxLicensesDepMap[""] = append(nonSpdxLicensesDepMap[""], key)
				continue
			}

			// Listed under every license it names, so an OR with a copyleft license counts as copyleft.
			spdx := map[string]bool{}
			for _, id := range ids {
				isSpdx, err := source.IsSpdxLicense(id)
				if err != nil {
					return types.WorkSpaceLicenseInfoInternal{}, fmt.Errorf("%w: SPDX check of %s: %w", ErrKnowledgeLookup, id, err)
				}
				spdx[id] = isSpdx
				if !isSpdx {
					nonSpdxLicensesDepMap[id] = append(nonSpdxLicensesDepMap[id], key)
					continue
				}
				licensesDepMap[id] = append(licensesDepMap[id], key)
			}
			// A policy violation only when no OR alternative is allowed.
			blocked := BlockedLicenses(expression, func(id string) bool {
				return slices.Contains(licensePolicy.DisallowedLicense, id) && spdx[id]
			})
			for _, id := range blocked {
				licenseComplianceViolations[id] = append(licenseComplianceViolations[id], key)
			}
		}
	}

	return types.WorkSpaceLicenseInfoInternal{
		LicensesDepMap:              licensesDepMap,
		NonSpdxLicensesDepMap:       nonSpdxLicensesDepMap,
		LicenseComplianceViolations: licenseComplianceViolations,
	}, nil
}
