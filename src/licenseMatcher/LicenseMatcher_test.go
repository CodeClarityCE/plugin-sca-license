package matcher

import (
	"errors"
	"slices"
	"testing"

	sbomTypes "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/stretchr/testify/assert"
)

// fakeKnowledge serves package and version licenses and the SPDX list from maps, and can fail lookups.
type fakeKnowledge struct {
	packages    map[string]string
	versions    map[string]string // keyed by name@version
	spdx        []string
	languages   *[]string
	packageErr  error
	spdxErr     error
	lookupCount *int
}

func (f fakeKnowledge) count() {
	if f.lookupCount != nil {
		*f.lookupCount++
	}
}

func (f fakeKnowledge) PackageLicense(name, version, language string) (PackageLicenses, bool, error) {
	f.count()
	if f.languages != nil {
		*f.languages = append(*f.languages, language)
	}
	if f.packageErr != nil {
		return PackageLicenses{}, false, f.packageErr
	}
	license, ok := f.packages[name]
	return PackageLicenses{Version: f.versions[name+"@"+version], Package: license}, ok, nil
}

func (f fakeKnowledge) IsSpdxLicense(id string) (bool, error) {
	f.count()
	if f.spdxErr != nil {
		return false, f.spdxErr
	}
	return slices.Contains(f.spdx, id), nil
}

var spdxList = []string{"MIT", "BSD-3-Clause", "GPL-2.0", "GPL-2.0+", "Apache-2.0", "LGPL-2.1"}

func match(packages map[string]string, policy knowledge.LicensePolicy) (map[string][]string, map[string][]string, map[string][]string) {
	deps := map[string]map[string]sbomTypes.Versions{}
	for name := range packages {
		deps[name] = map[string]sbomTypes.Versions{"1.0.0": {}}
	}
	lm := LicenseMatcher{LicenseDataSource: LICENSE_DATA_SOURCE_DB}
	info, err := lm.MatchWorkSpaceLicenses(fakeKnowledge{packages: packages, spdx: spdxList}, deps, policy)
	if err != nil {
		panic(err)
	}
	return info.LicensesDepMap, info.NonSpdxLicensesDepMap, info.LicenseComplianceViolations
}

func TestSingleSpdxLicenseIsListedUnderItsId(t *testing.T) {
	spdx, nonSpdx, _ := match(map[string]string{"left-pad": "MIT"}, knowledge.LicensePolicy{})

	assert.Equal(t, map[string][]string{"MIT": {"left-pad@1.0.0"}}, spdx)
	assert.Empty(t, nonSpdx)
}

func TestOrExpressionIsListedUnderEveryLicenseItNames(t *testing.T) {
	spdx, nonSpdx, _ := match(map[string]string{"node-forge": "(BSD-3-Clause OR GPL-2.0)"}, knowledge.LicensePolicy{})

	assert.Equal(t, map[string][]string{
		"BSD-3-Clause": {"node-forge@1.0.0"},
		"GPL-2.0":      {"node-forge@1.0.0"},
	}, spdx)
	assert.Empty(t, nonSpdx)
}

func TestAndExpressionWithNestingAndExceptionIsSplit(t *testing.T) {
	spdx, nonSpdx, _ := match(map[string]string{
		"pkg": "MIT AND (Apache-2.0 OR GPL-2.0+ WITH Classpath-exception-2.0)",
	}, knowledge.LicensePolicy{})

	assert.Equal(t, map[string][]string{
		"MIT":        {"pkg@1.0.0"},
		"Apache-2.0": {"pkg@1.0.0"},
		"GPL-2.0+":   {"pkg@1.0.0"},
	}, spdx)
	assert.Empty(t, nonSpdx)
}

func TestLowercaseOperatorsAreAccepted(t *testing.T) {
	spdx, _, _ := match(map[string]string{"pkg": "MIT or LGPL-2.1"}, knowledge.LicensePolicy{})

	assert.Equal(t, map[string][]string{
		"MIT":      {"pkg@1.0.0"},
		"LGPL-2.1": {"pkg@1.0.0"},
	}, spdx)
}

func TestNonSpdxPartIsKeptByItsOwnText(t *testing.T) {
	spdx, nonSpdx, _ := match(map[string]string{"rgbcolor": "MIT OR SEE LICENSE IN FEEL-FREE.md"}, knowledge.LicensePolicy{})

	assert.Equal(t, map[string][]string{"MIT": {"rgbcolor@1.0.0"}}, spdx)
	assert.Equal(t, map[string][]string{"SEE LICENSE IN FEEL-FREE.md": {"rgbcolor@1.0.0"}}, nonSpdx)
}

func TestDependencyUsesItsVersionsLicense(t *testing.T) {
	deps := map[string]map[string]sbomTypes.Versions{"glob": {"7.1.2": {}, "9.0.0": {}}}
	source := fakeKnowledge{
		packages: map[string]string{"glob": "BlueOak-1.0.0"},
		versions: map[string]string{"glob@7.1.2": "ISC"},
		spdx:     []string{"ISC", "BlueOak-1.0.0"},
	}
	lm := LicenseMatcher{LicenseDataSource: LICENSE_DATA_SOURCE_DB}
	info, err := lm.MatchWorkSpaceLicenses(source, deps, knowledge.LicensePolicy{})

	assert.NoError(t, err)
	// 9.0.0 has no version license recorded, so it falls back to the package license.
	assert.Equal(t, map[string][]string{
		"ISC":           {"glob@7.1.2"},
		"BlueOak-1.0.0": {"glob@9.0.0"},
	}, info.LicensesDepMap)
}

func TestLookupAsksForTheMatchersLanguage(t *testing.T) {
	var languages []string
	deps := map[string]map[string]sbomTypes.Versions{"psr/log": {"3.0.0": {}}}
	source := fakeKnowledge{packages: map[string]string{"psr/log": "MIT"}, spdx: spdxList, languages: &languages}
	lm := LicenseMatcher{LicenseDataSource: LICENSE_DATA_SOURCE_DB, Language: "php"}

	_, err := lm.MatchWorkSpaceLicenses(source, deps, knowledge.LicensePolicy{})

	assert.NoError(t, err)
	assert.Equal(t, []string{"php"}, languages)
}

func TestUnknownPackageIsKeptWithoutALicense(t *testing.T) {
	deps := map[string]map[string]sbomTypes.Versions{"ghost": {"1.0.0": {}}}
	lm := LicenseMatcher{LicenseDataSource: LICENSE_DATA_SOURCE_DB}
	info, err := lm.MatchWorkSpaceLicenses(fakeKnowledge{spdx: spdxList}, deps, knowledge.LicensePolicy{})

	assert.NoError(t, err)
	assert.Empty(t, info.LicensesDepMap)
	assert.Equal(t, map[string][]string{"": {"ghost@1.0.0"}}, info.NonSpdxLicensesDepMap)
}

func TestFailedPackageLookupStopsTheRun(t *testing.T) {
	lookups := 0
	deps := map[string]map[string]sbomTypes.Versions{"a": {"1.0.0": {}}, "b": {"1.0.0": {}}, "c": {"1.0.0": {}}}
	lm := LicenseMatcher{LicenseDataSource: LICENSE_DATA_SOURCE_DB}
	source := fakeKnowledge{spdx: spdxList, packageErr: errors.New("dial tcp pgbouncer:6432: connection refused"), lookupCount: &lookups}

	_, err := lm.MatchWorkSpaceLicenses(source, deps, knowledge.LicensePolicy{})

	assert.ErrorIs(t, err, ErrKnowledgeLookup)
	assert.Equal(t, 1, lookups, "no lookup starts after the first failure")
}

func TestFailedSpdxCheckFailsTheRun(t *testing.T) {
	deps := map[string]map[string]sbomTypes.Versions{"left-pad": {"1.0.0": {}}}
	lm := LicenseMatcher{LicenseDataSource: LICENSE_DATA_SOURCE_DB}
	source := fakeKnowledge{packages: map[string]string{"left-pad": "MIT"}, spdxErr: errors.New("i/o timeout")}

	_, err := lm.MatchWorkSpaceLicenses(source, deps, knowledge.LicensePolicy{DisallowedLicense: []string{"MIT"}})

	assert.ErrorIs(t, err, ErrKnowledgeLookup)
}

func TestOrExpressionWithAnAllowedAlternativeIsNotAViolation(t *testing.T) {
	policy := knowledge.LicensePolicy{DisallowedLicense: []string{"GPL-2.0"}}
	spdx, _, violations := match(map[string]string{"node-forge": "(BSD-3-Clause OR GPL-2.0)"}, policy)

	assert.Empty(t, violations)
	// Still listed under GPL-2.0, so the copyleft count includes it.
	assert.Equal(t, []string{"node-forge@1.0.0"}, spdx["GPL-2.0"])
}

func TestOrExpressionWithEveryAlternativeDisallowedIsAViolation(t *testing.T) {
	policy := knowledge.LicensePolicy{DisallowedLicense: []string{"GPL-2.0", "LGPL-2.1"}}
	_, _, violations := match(map[string]string{"pkg": "GPL-2.0 OR LGPL-2.1"}, policy)

	assert.Equal(t, map[string][]string{
		"GPL-2.0":  {"pkg@1.0.0"},
		"LGPL-2.1": {"pkg@1.0.0"},
	}, violations)
}

func TestDisallowedLicenseInAnAndExpressionIsAViolation(t *testing.T) {
	policy := knowledge.LicensePolicy{DisallowedLicense: []string{"GPL-2.0"}}
	_, _, violations := match(map[string]string{"pkg": "MIT AND GPL-2.0"}, policy)

	assert.Equal(t, map[string][]string{"GPL-2.0": {"pkg@1.0.0"}}, violations)
}

func TestAndBindsTighterThanOr(t *testing.T) {
	policy := knowledge.LicensePolicy{DisallowedLicense: []string{"GPL-2.0"}}
	_, _, violations := match(map[string]string{"pkg": "MIT AND GPL-2.0 OR Apache-2.0"}, policy)

	assert.Empty(t, violations)
}

func TestNestedExpressionNeedsAnAllowedChoiceInEveryAndPart(t *testing.T) {
	expression := "MIT AND (Apache-2.0 OR GPL-2.0+ WITH Classpath-exception-2.0)"

	_, _, oneBlocked := match(map[string]string{"pkg": expression},
		knowledge.LicensePolicy{DisallowedLicense: []string{"GPL-2.0+"}})
	_, _, bothBlocked := match(map[string]string{"pkg": expression},
		knowledge.LicensePolicy{DisallowedLicense: []string{"GPL-2.0+", "Apache-2.0"}})

	assert.Empty(t, oneBlocked)
	assert.Equal(t, map[string][]string{
		"Apache-2.0": {"pkg@1.0.0"},
		"GPL-2.0+":   {"pkg@1.0.0"},
	}, bothBlocked)
}
