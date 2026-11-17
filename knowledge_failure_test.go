package main

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	sbomTypes "github.com/CodeClarityCE/plugin-sbom-javascript/src/types/sbom/js"
	license "github.com/CodeClarityCE/plugin-sca-license/src"
	"github.com/CodeClarityCE/plugin-sca-license/src/types"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	knowledge "github.com/CodeClarityCE/utility-types/knowledge_db"
	"github.com/google/uuid"
)

// stubKnowledge answers every package with one license, or fails every lookup.
type stubKnowledge struct {
	licenses map[string]string
	err      error
}

func (s stubKnowledge) PackageLicense(name string) (string, bool, error) {
	if s.err != nil {
		return "", false, s.err
	}
	l, ok := s.licenses[name]
	return l, ok, nil
}

func (s stubKnowledge) IsSpdxLicense(id string) (bool, error) {
	return id == "MIT", s.err
}

func oneDependencySbom(name string) sbomTypes.Output {
	return sbomTypes.Output{
		WorkSpaces: map[string]sbomTypes.WorkSpace{
			".": {Dependencies: map[string]map[string]sbomTypes.Versions{name: {"1.0.0": {Direct: true}}}},
		},
		AnalysisInfo: sbomTypes.AnalysisInfo{Status: codeclarity.SUCCESS},
	}
}

func analyzeWith(source stubKnowledge, dependency string) (types.Output, string) {
	keys := []sbomKey{{uuid.New(), "JS", "js-sbom"}}
	return combineLicenseOutputs(keys, func(sbomKey) (types.Output, error) {
		return license.StartWithKnowledge(source, oneDependencySbom(dependency), "JS", knowledge.LicensePolicy{}, time.Now())
	}, time.Now())
}

func TestFailedLicenseLookupFailsTheStepWithAReadableReason(t *testing.T) {
	raw := errors.New(`pgdriver: SASL: read tcp 10.0.0.5:4242->pgbouncer:6432: i/o timeout SELECT "package"."name"`)

	out, reason := analyzeWith(stubKnowledge{err: raw}, "left-pad")

	if out.AnalysisInfo.Status != codeclarity.FAILURE {
		t.Fatalf("status = %s, want failure", out.AnalysisInfo.Status)
	}
	if reason != knowledgeLookupReason {
		t.Fatalf("reason = %q", reason)
	}
	for _, leak := range []string{"pgbouncer", "6432", "SELECT", "pgdriver"} {
		if strings.Contains(reason, leak) {
			t.Fatalf("reason %q leaks %q", reason, leak)
		}
	}
}

func TestPackageMissingFromKnowledgeStillSucceeds(t *testing.T) {
	out, reason := analyzeWith(stubKnowledge{licenses: map[string]string{}}, "ghost")

	if out.AnalysisInfo.Status != codeclarity.SUCCESS || reason != "" {
		t.Fatalf("status = %s, reason = %q", out.AnalysisInfo.Status, reason)
	}
	if got := fmt.Sprint(out.WorkSpaces["."].NonSpdxLicensesDepMap[""]); got != "[ghost@1.0.0]" {
		t.Fatalf("unknown license key holds %s", got)
	}
}

func TestNonSpdxLicenseStillLandsUnderItsOwnKey(t *testing.T) {
	out, _ := analyzeWith(stubKnowledge{licenses: map[string]string{"odd": "SEE LICENSE IN LICENSE.md"}}, "odd")

	if out.AnalysisInfo.Status != codeclarity.SUCCESS {
		t.Fatalf("status = %s", out.AnalysisInfo.Status)
	}
	if got := fmt.Sprint(out.WorkSpaces["."].NonSpdxLicensesDepMap["SEE LICENSE IN LICENSE.md"]); got != "[odd@1.0.0]" {
		t.Fatalf("non-SPDX key holds %s", got)
	}
}
