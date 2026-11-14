package matcher

import (
	"slices"
	"strings"
)

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

// BlockedLicenses returns the disallowed licenses that stop an SPDX expression from being met,
// or nothing when some choice of OR alternatives uses only allowed licenses. AND binds tighter than OR.
func BlockedLicenses(expression string, disallowed func(id string) bool) []string {
	p := &expressionParser{tokens: strings.Fields(strings.NewReplacer("(", " ( ", ")", " ) ").Replace(expression))}
	ok, blocked := p.or(disallowed)
	if ok {
		return nil
	}
	return blocked
}

type expressionParser struct {
	tokens []string
	pos    int
}

func (p *expressionParser) peek() string {
	if p.pos < len(p.tokens) {
		return strings.ToUpper(p.tokens[p.pos])
	}
	return ""
}

func (p *expressionParser) or(disallowed func(string) bool) (bool, []string) {
	ok, blocked := p.and(disallowed)
	for p.peek() == "OR" {
		p.pos++
		nextOk, nextBlocked := p.and(disallowed)
		ok = ok || nextOk
		blocked = appendNew(blocked, nextBlocked...)
	}
	if ok {
		return true, nil
	}
	return false, blocked
}

func (p *expressionParser) and(disallowed func(string) bool) (bool, []string) {
	ok, blocked := p.term(disallowed)
	for p.peek() == "AND" {
		p.pos++
		nextOk, nextBlocked := p.term(disallowed)
		ok = ok && nextOk
		blocked = appendNew(blocked, nextBlocked...)
	}
	return ok, blocked
}

func (p *expressionParser) term(disallowed func(string) bool) (bool, []string) {
	if p.peek() == "(" {
		p.pos++
		ok, blocked := p.or(disallowed)
		if p.peek() == ")" {
			p.pos++
		}
		return ok, blocked
	}
	words := []string{}
	skipping := false
	for p.pos < len(p.tokens) {
		switch p.peek() {
		case "(", ")", "OR", "AND":
			return leaf(strings.Join(words, " "), disallowed)
		case "WITH":
			skipping = true
		default:
			if !skipping {
				words = append(words, p.tokens[p.pos])
			}
		}
		p.pos++
	}
	return leaf(strings.Join(words, " "), disallowed)
}

func leaf(id string, disallowed func(string) bool) (bool, []string) {
	if id == "" || !disallowed(id) {
		return true, nil
	}
	return false, []string{id}
}

func appendNew(list []string, items ...string) []string {
	for _, item := range items {
		if !slices.Contains(list, item) {
			list = append(list, item)
		}
	}
	return list
}
