package matcher

import "strings"

// LicenseIDs returns the licenses an SPDX expression names, in order and without repeats.
// AND and OR both list every license; a WITH exception is dropped.
func LicenseIDs(expression string) []string {
	spaced := strings.NewReplacer("(", " ( ", ")", " ) ").Replace(expression)
	ids := []string{}
	seen := map[string]bool{}
	words := []string{}
	skipping := false

	flush := func() {
		if len(words) > 0 {
			id := strings.Join(words, " ")
			if !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
		words = words[:0]
		skipping = false
	}

	for _, token := range strings.Fields(spaced) {
		switch strings.ToUpper(token) {
		case "(", ")", "OR", "AND":
			flush()
		case "WITH":
			skipping = true
		default:
			if !skipping {
				words = append(words, token)
			}
		}
	}
	flush()
	return ids
}
