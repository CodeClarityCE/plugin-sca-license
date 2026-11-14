package main

import (
	"errors"
	"testing"
	"time"

	"github.com/CodeClarityCE/plugin-sca-license/src/types"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	"github.com/google/uuid"
)

func licenseOutput(status codeclarity.AnalysisStatus, workspace string) types.Output {
	output := types.Output{WorkSpaces: map[string]types.WorkSpaceLicenseInfo{workspace: {}}}
	output.AnalysisInfo.Status = status
	return output
}

func TestCombineLicenseOutputs(t *testing.T) {
	keys := []sbomKey{{uuid.New(), "JS", "js-sbom"}, {uuid.New(), "PHP", "php-sbom"}}
	ok := func(k sbomKey) (types.Output, error) { return licenseOutput(codeclarity.SUCCESS, k.language), nil }
	cases := []struct {
		name    string
		php     func(sbomKey) (types.Output, error)
		want    codeclarity.AnalysisStatus
		wantLen int
	}{
		{"every SBOM succeeds", ok, codeclarity.SUCCESS, 2},
		{"an SBOM cannot be loaded", func(sbomKey) (types.Output, error) { return types.Output{}, errors.New("load failed") }, codeclarity.FAILURE, 0},
		{"an SBOM cannot be processed", func(sbomKey) (types.Output, error) { return licenseOutput(codeclarity.FAILURE, "php"), nil }, codeclarity.FAILURE, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, _ := combineLicenseOutputs(keys, func(k sbomKey) (types.Output, error) {
				if k.language == "PHP" {
					return tc.php(k)
				}
				return ok(k)
			}, time.Now())
			if out.AnalysisInfo.Status != tc.want || len(out.WorkSpaces) != tc.wantLen {
				t.Fatalf("status = %s with %d workspaces", out.AnalysisInfo.Status, len(out.WorkSpaces))
			}
		})
	}
}

func TestCombineLicenseOutputsSaysWhichSbomFailed(t *testing.T) {
	keys := []sbomKey{{uuid.New(), "JS", "js-sbom"}, {uuid.New(), "PHP", "php-sbom"}}
	success := func(k sbomKey) types.Output {
		output := types.Output{WorkSpaces: map[string]types.WorkSpaceLicenseInfo{k.language: {}}}
		output.AnalysisInfo.Status = codeclarity.SUCCESS
		return output
	}
	failure := types.Output{}
	failure.AnalysisInfo.Status = codeclarity.FAILURE
	cases := []struct {
		name    string
		analyze func(sbomKey) (types.Output, error)
		want    string
	}{
		{"cannot be loaded", func(k sbomKey) (types.Output, error) {
			if k.language == "PHP" {
				return types.Output{}, errors.New("pq: secret detail at /srv/x")
			}
			return success(k), nil
		}, "the PHP dependency list could not be read"},
		{"cannot be processed", func(sbomKey) (types.Output, error) { return failure, nil }, "the licenses of the JavaScript dependencies could not be checked"},
		{"every SBOM succeeds", func(k sbomKey) (types.Output, error) { return success(k), nil }, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, reason := combineLicenseOutputs(keys, tc.analyze, time.Now())
			if reason != tc.want {
				t.Fatalf("reason = %q, want %q", reason, tc.want)
			}
		})
	}
}
