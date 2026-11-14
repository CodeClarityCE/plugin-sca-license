package main

import (
	"testing"

	codeclarity "github.com/CodeClarityCE/utility-types/codeclarity_db"
)

func TestSbomKeysIgnoresSkippedSteps(t *testing.T) {
	jsKey := "11111111-1111-1111-1111-111111111111"
	phpKey := "22222222-2222-2222-2222-222222222222"
	cases := []struct {
		name  string
		steps [][]codeclarity.Step
		want  map[string]string
	}{
		{
			name: "both ecosystems",
			steps: [][]codeclarity.Step{{
				{Name: "js-sbom", Status: codeclarity.SUCCESS, Result: map[string]any{"sbomKey": jsKey}},
				{Name: "php-sbom", Status: codeclarity.SUCCESS, Result: map[string]any{"sbomKey": phpKey}},
			}},
			want: map[string]string{"JS": jsKey, "PHP": phpKey},
		},
		{
			name: "skipped step has no result",
			steps: [][]codeclarity.Step{{
				{Name: "js-sbom", Status: codeclarity.SKIPPED, Result: map[string]any{"skip_reason": "php only"}},
				{Name: "php-sbom", Status: codeclarity.SUCCESS, Result: map[string]any{"sbomKey": phpKey}},
			}},
			want: map[string]string{"PHP": phpKey},
		},
		{
			name: "SBOMs in different earlier stages",
			steps: [][]codeclarity.Step{
				{{Name: "js-sbom", Status: codeclarity.SUCCESS, Result: map[string]any{"sbomKey": jsKey}}},
				{{Name: "php-sbom", Status: codeclarity.SUCCESS, Result: map[string]any{"sbomKey": phpKey}}},
			},
			want: map[string]string{"JS": jsKey, "PHP": phpKey},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := sbomKeysFromSteps(tc.steps)
			if len(got) != len(tc.want) {
				t.Fatalf("got %+v, want %v", got, tc.want)
			}
			for _, key := range got {
				if tc.want[key.language] != key.id.String() {
					t.Errorf("%s key = %s, want %s", key.language, key.id, tc.want[key.language])
				}
			}
		})
	}
}
