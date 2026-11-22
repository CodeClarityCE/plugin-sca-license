package main

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	sbomTypes "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js"
	license "github.com/CodeClarityCE/plugin-sca-license/src"
	matcher "github.com/CodeClarityCE/plugin-sca-license/src/licenseMatcher"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
)

// License expressions taken from the license matcher tests.
var licenseSeeds = []string{
	"", "MIT", "(BSD-3-Clause OR GPL-2.0)", "MIT or LGPL-2.1", "MIT OR SEE LICENSE IN FEEL-FREE.md",
	"(MIT AND Apache-2.0) OR GPL-2.0+", "UNLICENSED",
}

// Fixtures are cut to this many packages per workspace, since big seeds stall the fuzzer.
const seedPackages = 4

// smallSbom returns a fixture SBOM as compact JSON with only its first few packages.
func smallSbom(f *testing.F, data []byte) []byte {
	sbom := sbomTypes.Output{}
	if err := json.Unmarshal(data, &sbom); err != nil {
		f.Fatal(err)
	}
	for key, workspace := range sbom.WorkSpaces {
		names := slices.Sorted(maps.Keys(workspace.Dependencies))
		for _, name := range names[min(seedPackages, len(names)):] {
			delete(workspace.Dependencies, name)
		}
		sbom.WorkSpaces[key] = workspace
	}
	small, err := json.Marshal(sbom)
	if err != nil {
		f.Fatal(err)
	}
	return small
}

// anyLicenseKnowledge gives every package the same license and knows a few SPDX ids.
type anyLicenseKnowledge struct{ license string }

func (k anyLicenseKnowledge) PackageLicense(name, version, language string) (matcher.PackageLicenses, bool, error) {
	return matcher.PackageLicenses{Version: k.license, Package: k.license}, true, nil
}

func (k anyLicenseKnowledge) IsSpdxLicense(id string) (bool, error) {
	switch id {
	case "MIT", "BSD-3-Clause", "GPL-2.0", "GPL-2.0+", "Apache-2.0", "LGPL-2.1":
		return true, nil
	}
	return false, nil
}

// FuzzReadSbom checks that reading any stored SBOM, then matching its licenses, never panics.
func FuzzReadSbom(f *testing.F) {
	paths, err := filepath.Glob(filepath.Join("testdata", "sbom", "*", "sbom.json"))
	if err != nil || len(paths) == 0 {
		f.Fatalf("no SBOM fixtures: %v", err)
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			f.Fatal(err)
		}
		seed := smallSbom(f, data)
		for _, l := range licenseSeeds {
			f.Add(seed, l)
		}
	}

	policy := knowledge.LicensePolicy{DisallowedLicense: []string{"GPL-2.0", "LGPL-2.1"}}
	f.Fuzz(func(t *testing.T, data []byte, packageLicense string) {
		sbom := sbomTypes.Output{}
		if err := json.Unmarshal(data, &sbom); err != nil {
			return
		}
		for _, language := range []string{"JS", "PHP"} {
			_, _ = license.StartWithKnowledge(anyLicenseKnowledge{packageLicense}, sbom, language, policy, time.Now())
		}
	})
}
