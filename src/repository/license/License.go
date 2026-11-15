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

// GetPackageLicense returns the license expression the knowledge base holds for a package.
// It is the package's latest license, whatever version is asked about.
func GetPackageLicense(knowledge_db *bun.DB, depName string) (string, error) {
	var dependency knowledge.Package
	err := knowledge_db.NewSelect().Model(&dependency).Where("name = ?", depName).Scan(context.Background(), &dependency)
	if err != nil {
		return "", err
	}
	return dependency.License, nil
}
