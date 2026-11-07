package kubernetes

import "slices"

// CompiledRules validates and freezes a rule set once, then narrows each exact
// request to relevant API groups. Work reports real candidate comparisons so
// callers can preserve a bound without revalidating every unrelated rule.
type CompiledRules struct {
	groups map[string][]ScopedRule
	urls   []ScopedRule
}

func CompileRules(rules []ScopedRule) (*CompiledRules, error) {
	if len(rules) > 16384 {
		return nil, ErrInvalid
	}
	out := &CompiledRules{groups: map[string][]ScopedRule{}}
	for _, r := range rules {
		if r.Rule.Validate() != nil || !bounded(r.Namespace, true, 253) {
			return nil, ErrInvalid
		}
		r.Rule.APIGroups = slices.Clone(r.Rule.APIGroups)
		r.Rule.Resources = slices.Clone(r.Rule.Resources)
		r.Rule.Verbs = slices.Clone(r.Rule.Verbs)
		r.Rule.ResourceNames = slices.Clone(r.Rule.ResourceNames)
		r.Rule.NonResourceURLs = slices.Clone(r.Rule.NonResourceURLs)
		if len(r.Rule.NonResourceURLs) > 0 {
			out.urls = append(out.urls, r)
		} else {
			for _, group := range r.Rule.APIGroups {
				out.groups[group] = append(out.groups[group], r)
			}
		}
	}
	return out, nil
}

func (r *CompiledRules) Allows(p Permission) (bool, int, error) {
	if r == nil || p.Validate() != nil {
		return false, 1, ErrInvalid
	}
	work := 1
	if p.NonResourceURL != "" {
		for _, rule := range r.urls {
			work++
			if rule.allows(p) {
				return true, work, nil
			}
		}
		return false, work, nil
	}
	for _, group := range []string{p.APIGroup, "*"} {
		for _, rule := range r.groups[group] {
			work++
			if rule.allows(p) {
				return true, work, nil
			}
		}
	}
	return false, work, nil
}
