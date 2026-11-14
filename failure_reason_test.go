package main

import (
	"strings"
	"testing"

	amqp "github.com/CodeClarityCE/utility-types/amqp"
	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
	plugin_db "github.com/CodeClarityCE/utility-types/plugin_db"
)

func TestStartAnalysisReportsWhyItFailed(t *testing.T) {
	cfg := plugin_db.Plugin{Name: "license-finder"}
	policy := map[string]any{"license-finder": map[string]any{}}
	sbomStage := func(name string, result map[string]any) [][]codeclarity.Step {
		return [][]codeclarity.Step{{{Name: name, Status: codeclarity.SUCCESS, Result: result}}}
	}
	cases := []struct {
		name     string
		analysis codeclarity.Analysis
		want     string
	}{
		{"settings are missing", codeclarity.Analysis{}, "license policy settings"},
		{"policy is not a list", codeclarity.Analysis{Config: map[string]any{"license-finder": map[string]any{"licensePolicy": "MIT"}}}, "license policy is not valid"},
		{"policy entry is not text", codeclarity.Analysis{Config: map[string]any{"license-finder": map[string]any{"licensePolicy": []any{1}}}}, "license policy is not valid"},
		{"SBOM result has no key", codeclarity.Analysis{Config: policy, Stage: 1, Steps: sbomStage("js-sbom", map[string]any{"other": 1})}, "JavaScript dependency list"},
		{"SBOM key is invalid", codeclarity.Analysis{Config: policy, Stage: 1, Steps: sbomStage("php-sbom", map[string]any{"sbomKey": "nope"})}, "PHP dependency list"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, status, err := startAnalysis(nil, amqp.DispatcherPluginMessage{}, cfg, tc.analysis)
			if err != nil {
				t.Fatalf("a returned error loses the reason, got %v", err)
			}
			if status != codeclarity.FAILURE {
				t.Fatalf("status = %s", status)
			}
			reason, _ := result[codeclarity.StepFailureReasonKey].(string)
			if !strings.Contains(reason, tc.want) {
				t.Fatalf("reason = %q, want it to mention %q", reason, tc.want)
			}
		})
	}
}
