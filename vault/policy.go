package vault

func matchRune(pattern, str []rune) bool {
	for len(pattern) > 0 {
		switch pattern[0] {
		default:
			if len(str) == 0 || str[0] != pattern[0] {
				return false
			}
		case '*':
			return matchRune(pattern[1:], str) ||
				(len(str) > 0 && matchRune(pattern, str[1:]))
		case '.':
			return matchRune(pattern[2:], str) ||
				(len(str) > 0 && matchRune(pattern, str[1:]))
		}
		str = str[1:]
		pattern = pattern[1:]
	}
	return len(str) == 0 && len(pattern) == 0
}

func Match(pattern, str string) bool {
	if pattern == "" {
		return str == pattern
	}
	if pattern == "*" {
		return true
	}
	return matchRune([]rune(pattern), []rune(str))
}

func containsAction(p *Policy, action PolicyAction) bool {
	for _, a := range p.Actions {
		if a == action {
			return true
		}
	}
	return false
}

func EvaluateRequest(request Request, policies []*Policy) bool {
	allowed := false

	for _, p := range policies {
		// check that action exists in the policy
		matched := containsAction(p, request.Action)
		if !matched {
			// no matching action found in current policy
			continue
		}
		for _, resource := range p.Resources {
			if Match(resource, request.Resource) {
				if p.Effect == EffectDeny {
					// deny takes precendence
					return false
				}
				allowed = true
			}
		}
	}
	return allowed
}
