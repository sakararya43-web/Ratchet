package kubernetes

import (
	"slices"
	"strings"
)

// Covers proves rule coverage across a union, without expanding a wildcard to a
// finite list of today's API resources/verbs. It is used for Kubernetes' implicit
// bind/escalate restrictions; possessing edit permission alone is insufficient.
func Covers(have []ScopedRule, want []ScopedRule) (bool, error) {
	if len(have) > 16384 || len(want) > 16384 {
		return false, ErrInvalid
	}
	for _, r := range append(append([]ScopedRule(nil), have...), want...) {
		if r.Rule.Validate() != nil || !bounded(r.Namespace, true, 253) {
			return false, ErrInvalid
		}
	}
	work := 0
	for _, w := range want {
		if len(w.Rule.NonResourceURLs) > 0 {
			for _, verb := range w.Rule.Verbs {
				for _, url := range w.Rule.NonResourceURLs {
					covered := false
					for _, h := range have {
						work++
						if work > 2_000_000 {
							return false, ErrUnsupported
						}
						if (h.Namespace != "" && h.Namespace != w.Namespace) || !coversToken(h.Rule.Verbs, verb) {
							continue
						}
						for _, pattern := range h.Rule.NonResourceURLs {
							if coversURL(pattern, url) {
								covered = true
								break
							}
						}
						if covered {
							break
						}
					}
					if !covered {
						return false, nil
					}
				}
			}
			continue
		}
		names := w.Rule.ResourceNames
		if len(names) == 0 {
			names = []string{""}
		}
		for _, group := range w.Rule.APIGroups {
			for _, resource := range w.Rule.Resources {
				for _, verb := range w.Rule.Verbs {
					for _, name := range names {
						// The API's no-escalation rule comparator is structural:
						// even named top-level create rules must be covered here.
						// This differs deliberately from matching a concrete request.
						covered := false
						for _, h := range have {
							work++
							if work > 2_000_000 {
								return false, ErrUnsupported
							}
							if h.Namespace != "" && h.Namespace != w.Namespace {
								continue
							}
							if !coversToken(h.Rule.APIGroups, group) || !coversToken(h.Rule.Verbs, verb) || !coversResource(h.Rule.Resources, resource) {
								continue
							}
							if len(h.Rule.ResourceNames) == 0 || (name != "" && slices.Contains(h.Rule.ResourceNames, name)) {
								covered = true
								break
							}
						}
						if !covered {
							return false, nil
						}
					}
				}
			}
		}
	}
	return true, nil
}

func coversToken(patterns []string, value string) bool {
	return slices.Contains(patterns, "*") || (value != "*" && slices.Contains(patterns, value))
}

func coversResource(patterns []string, want string) bool {
	if slices.Contains(patterns, "*") || slices.Contains(patterns, want) {
		return true
	}
	if want == "*" {
		return false
	}
	if slash := strings.IndexByte(want, '/'); slash >= 0 {
		return slices.Contains(patterns, "*/"+want[slash+1:])
	}
	return false
}

func coversURL(have, want string) bool {
	if have == "*" || have == want {
		return true
	}
	return strings.HasSuffix(have, "*") && strings.HasPrefix(strings.TrimSuffix(want, "*"), strings.TrimSuffix(have, "*"))
}
