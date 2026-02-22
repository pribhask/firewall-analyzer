package terraform

import (
	"fmt"
	"regexp"
	"strings"
)

// SuricataRule represents a parsed Suricata/Snort-style rule.
type SuricataRule struct {
	Action      string
	Protocol    string
	SrcIP       string
	SrcPort     string
	Direction   string
	DstIP       string
	DstPort     string
	Message     string
	SID         string
	RuleOptions map[string]string
	Raw         string
}

// ruleHeaderPattern matches: action proto src_ip src_port direction dst_ip dst_port (options)
// Example: alert tcp any any -> 10.0.0.0/8 443 (msg:"Allow HTTPS"; sid:1;)
var ruleHeaderPattern = regexp.MustCompile(
	`^\s*(\w+)\s+(\w+)\s+(\S+)\s+(\S+)\s+(->|<>|<-)\s+(\S+)\s+(\S+)\s*\((.+)\)\s*$`,
)

// optionPattern matches key:value or key pairs within rule options.
var optionPattern = regexp.MustCompile(`(\w+)(?::([^;]+))?;`)

// ParseSuricataRules parses a multi-line Suricata rules string and returns
// individual parsed rules. Lines starting with # are treated as comments and skipped.
func ParseSuricataRules(rulesString string) ([]SuricataRule, error) {
	var rules []SuricataRule
	var parseErrors []string

	lines := strings.Split(rulesString, "\n")
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		rule, err := parseSuricataRule(line)
		if err != nil {
			parseErrors = append(parseErrors, fmt.Sprintf("line %d: %v", i+1, err))
			continue
		}

		rules = append(rules, *rule)
	}

	// Return both rules and aggregate parse errors so callers can decide severity.
	if len(parseErrors) > 0 && len(rules) == 0 {
		return nil, fmt.Errorf("no valid rules found; parse errors: %s",
			strings.Join(parseErrors, "; "))
	}

	return rules, nil
}

// parseSuricataRule parses a single Suricata rule line.
func parseSuricataRule(line string) (*SuricataRule, error) {
	matches := ruleHeaderPattern.FindStringSubmatch(line)
	if matches == nil {
		return nil, fmt.Errorf("line does not match Suricata rule format: %q", truncate(line, 80))
	}

	rule := &SuricataRule{
		Action:      strings.ToLower(matches[1]),
		Protocol:    strings.ToLower(matches[2]),
		SrcIP:       matches[3],
		SrcPort:     matches[4],
		Direction:   matches[5],
		DstIP:       matches[6],
		DstPort:     matches[7],
		Raw:         line,
		RuleOptions: make(map[string]string),
	}

	optionsBody := matches[8]
	optMatches := optionPattern.FindAllStringSubmatch(optionsBody, -1)
	for _, om := range optMatches {
		key := strings.TrimSpace(om[1])
		value := strings.TrimSpace(om[2])
		// Strip surrounding quotes from string values.
		value = strings.Trim(value, `"`)
		rule.RuleOptions[key] = value

		switch key {
		case "msg":
			rule.Message = value
		case "sid":
			rule.SID = value
		}
	}

	return rule, nil
}

// truncate returns a string truncated to maxLen characters with "..." appended if truncated.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// SuricataActionChanged reports whether the action changed between two rules with the same SID.
func SuricataActionChanged(before, after SuricataRule) bool {
	return before.Action != after.Action
}

// IndexRulesBySID indexes a slice of rules by their SID for efficient lookup.
func IndexRulesBySID(rules []SuricataRule) map[string]SuricataRule {
	idx := make(map[string]SuricataRule, len(rules))
	for _, r := range rules {
		if r.SID != "" {
			idx[r.SID] = r
		}
	}
	return idx
}
