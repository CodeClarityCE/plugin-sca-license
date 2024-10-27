package licenses

import (
	"context"

	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/uptrace/bun"
)

// GetSPDXLicenseByName retrieves an SPDX license by its name from the database.
// It takes the name of the license as a parameter and returns a pointer to the license and an error, if any.
func GetSPDXLicenseByName(name string, knowledge_db *bun.DB) (knowledge.License, error) {
	var license knowledge.License
	err := knowledge_db.NewSelect().Model(&license).Where("licenses.licenseId = ?", name).Scan(context.Background())
	if err != nil {
		return license, err
	}

	return license, nil
}

// GetDependencyLicenses retrieves the licenses associated with a specific dependency.
// It takes the dependency name and version as input parameters and returns a slice of licenseTypes.License and an error.
// The function queries the database to find the licenses associated with the given dependency and constructs a list of licenses.
// If the query construction or execution fails, an error is returned.
// The licenses are returned as a slice of licenseTypes.License.
func GetDependencyLicenses(knowledge_db *bun.DB, depName string, depVersion string) ([]knowledge.License, error) {
	var dependency knowledge.Package

	err := knowledge_db.NewSelect().Model(&dependency).Where("name = ?", depName).Scan(context.Background(), &dependency)
	if err != nil {
		return nil, err
	}

	var license knowledge.License
	err = knowledge_db.NewSelect().Model(&license).Where("\"licenseId\" = ?", dependency.License).Scan(context.Background())
	if err != nil {
		return nil, err
	}

	return []knowledge.License{license}, nil
}
