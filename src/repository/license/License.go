package licenses

import (
	"context"

	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

// GetSPDXLicenseByName retrieves an SPDX license by its identifier.
func GetSPDXLicenseByName(name string, knowledge_db *bun.DB) (knowledge.License, error) {
	var license knowledge.License
	err := knowledge_db.NewSelect().Model(&license).Where("\"licenseId\" = ?", name).Scan(context.Background())
	return license, err
}

// GetPackageLicense returns a package's license and the given version's license from the knowledge base.
// The version license is empty when the version row is missing or has none recorded.
func GetPackageLicense(knowledge_db *bun.DB, name, version, language string) (packageLicense string, versionLicense string, err error) {
	var row struct {
		PackageLicense string `bun:"package_license"`
		VersionLicense string `bun:"version_license"`
	}
	err = knowledge_db.NewSelect().
		TableExpr("package AS p").
		ColumnExpr("COALESCE(p.license, '') AS package_license").
		ColumnExpr("COALESCE(v.extra->>?, '') AS version_license", VersionLicenseKey).
		Join("LEFT JOIN version AS v ON v.package_id = p.id AND v.version = ?", version).
		Where("p.name = ? AND p.language = ?", name, language).
		Limit(1).
		Scan(context.Background(), &row)
	return row.PackageLicense, row.VersionLicense, err
}

// VersionLicenseKey is the version extra key where the knowledge service stores a version's license expression.
const VersionLicenseKey = "license_expression"
