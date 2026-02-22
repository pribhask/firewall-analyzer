package terraform

import (
	"fmt"
	"net"
	"strings"
)

// ChangeType categorizes the nature of a detected change.
type ChangeType string

const (
	ChangeTypeNewResource      ChangeType = "new_resource"
	ChangeTypeDeletedResource  ChangeType = "deleted_resource"
	ChangeTypeCIDRWidened      ChangeType = "cidr_widened"
	ChangeTypeAnySourceAdded   ChangeType = "any_source_added"    // 0.0.0.0/0 introduced
	ChangeTypeActionChanged    ChangeType = "action_changed"
	ChangeTypeFQDNAdded        ChangeType = "fqdn_added"
	ChangeTypeFQDNWildcard     ChangeType = "fqdn_wildcard_added"
	ChangeTypeSuricataAction   ChangeType = "suricata_action_changed"
	ChangeTypeRulesStringAdded ChangeType = "rules_string_added"
	ChangeTypeAttributeChanged ChangeType = "attribute_changed"
	ChangeTypeRuleAdded        ChangeType = "rule_added"
	ChangeTypeRuleRemoved      ChangeType = "rule_removed"
)

// Severity indicates the security impact level of a change.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// RuleChange describes a single detected change in a firewall rule group.
type RuleChange struct {
	ChangeType    ChangeType
	Severity      Severity
	ResourceName  string
	Description   string
	Before        string
	After         string
	// RiskContribution is the points this change adds to the overall risk score.
	RiskContribution float64
}

// DiffResult aggregates all changes detected between two versions of a file.
type DiffResult struct {
	Changes     []RuleChange
	TotalRisk   float64
	HasFirewall bool // true if either version contained firewall resources
}

// Differ computes semantic differences between two parsed rule group files.
type Differ struct{}

// NewDiffer creates a new Differ.
func NewDiffer() *Differ {
	return &Differ{}
}

// Diff computes all semantic changes between the before and after versions of a Terraform file.
// Either argument may be nil (representing a file that didn't exist).
func (d *Differ) Diff(before, after *RuleGroupFile) (*DiffResult, error) {
	result := &DiffResult{}

	beforeGroups := make(map[string]RuleGroup)
	afterGroups := make(map[string]RuleGroup)

	if before != nil {
		for _, rg := range before.RuleGroups {
			beforeGroups[rg.Name] = rg
			result.HasFirewall = true
		}
	}
	if after != nil {
		for _, rg := range after.RuleGroups {
			afterGroups[rg.Name] = rg
			result.HasFirewall = true
		}
	}

	if !result.HasFirewall {
		return result, nil
	}

	// Detect new resources.
	for name, afterRG := range afterGroups {
		if _, exists := beforeGroups[name]; !exists {
			change := RuleChange{
				ChangeType:       ChangeTypeNewResource,
				Severity:         SeverityMedium,
				ResourceName:     name,
				Description:      fmt.Sprintf("New rule group %q added", name),
				After:            fmt.Sprintf("type=%s capacity=%d", afterRG.Type, afterRG.Capacity),
				RiskContribution: 2.0,
			}
			result.Changes = append(result.Changes, change)
		}
	}

	// Detect deleted resources.
	for name := range beforeGroups {
		if _, exists := afterGroups[name]; !exists {
			change := RuleChange{
				ChangeType:       ChangeTypeDeletedResource,
				Severity:         SeverityInfo,
				ResourceName:     name,
				Description:      fmt.Sprintf("Rule group %q deleted", name),
				RiskContribution: 0.0,
			}
			result.Changes = append(result.Changes, change)
		}
	}

	// Diff matching resources.
	for name, beforeRG := range beforeGroups {
		afterRG, exists := afterGroups[name]
		if !exists {
			continue
		}

		changes, err := d.diffRuleGroups(name, beforeRG, afterRG)
		if err != nil {
			return nil, fmt.Errorf("diffing rule group %q: %w", name, err)
		}
		result.Changes = append(result.Changes, changes...)
	}

	for _, c := range result.Changes {
		result.TotalRisk += c.RiskContribution
	}

	return result, nil
}

func (d *Differ) diffRuleGroups(name string, before, after RuleGroup) ([]RuleChange, error) {
	var changes []RuleChange

	// Check top-level attribute changes.
	if before.Type != after.Type {
		changes = append(changes, RuleChange{
			ChangeType:       ChangeTypeAttributeChanged,
			Severity:         SeverityMedium,
			ResourceName:     name,
			Description:      "Rule group type changed",
			Before:           before.Type,
			After:            after.Type,
			RiskContribution: 1.5,
		})
	}

	if before.Capacity != after.Capacity && after.Capacity > before.Capacity {
		changes = append(changes, RuleChange{
			ChangeType:       ChangeTypeAttributeChanged,
			Severity:         SeverityLow,
			ResourceName:     name,
			Description:      "Rule group capacity increased",
			Before:           fmt.Sprintf("%d", before.Capacity),
			After:            fmt.Sprintf("%d", after.Capacity),
			RiskContribution: 0.5,
		})
	}

	// Diff rules source.
	rsChanges, err := d.diffRulesSources(name, before.RuleGroupConfig.RulesSource, after.RuleGroupConfig.RulesSource)
	if err != nil {
		return nil, err
	}
	changes = append(changes, rsChanges...)

	return changes, nil
}

func (d *Differ) diffRulesSources(resourceName string, before, after RulesSource) ([]RuleChange, error) {
	var changes []RuleChange

	// Diff stateful rules.
	statefulChanges := d.diffStatefulRules(resourceName, before.StatefulRules, after.StatefulRules)
	changes = append(changes, statefulChanges...)

	// Diff Suricata rules_string.
	if before.RulesString != after.RulesString {
		suricataChanges, err := d.diffSuricataRules(resourceName, before.RulesString, after.RulesString)
		if err != nil {
			// Non-fatal: include a generic change note.
			changes = append(changes, RuleChange{
				ChangeType:       ChangeTypeRulesStringAdded,
				Severity:         SeverityMedium,
				ResourceName:     resourceName,
				Description:      "Suricata rules_string changed (parse error: " + err.Error() + ")",
				Before:           before.RulesString,
				After:            after.RulesString,
				RiskContribution: 2.0,
			})
		} else {
			changes = append(changes, suricataChanges...)
		}
	}

	// Diff FQDN source list.
	if before.RulesSourceList != nil || after.RulesSourceList != nil {
		fqdnChanges := d.diffRulesSourceList(resourceName, before.RulesSourceList, after.RulesSourceList)
		changes = append(changes, fqdnChanges...)
	}

	return changes, nil
}

func (d *Differ) diffStatefulRules(resourceName string, before, after []StatefulRule) []RuleChange {
	var changes []RuleChange

	// Index before rules by a canonical key.
	beforeIdx := make(map[string]StatefulRule)
	for _, r := range before {
		key := statefulRuleKey(r)
		beforeIdx[key] = r
	}

	afterIdx := make(map[string]StatefulRule)
	for _, r := range after {
		key := statefulRuleKey(r)
		afterIdx[key] = r
	}

	// Find new and modified rules.
	for key, afterRule := range afterIdx {
		beforeRule, exists := beforeIdx[key]
		if !exists {
			// New rule.
			risk := 1.0
			severity := SeverityLow

			if afterRule.Action == "PASS" || afterRule.Action == "pass" {
				risk = 3.0
				severity = SeverityHigh
			}

			cidrChanges := d.analyzeCIDR(resourceName, "", afterRule.Header.Source, afterRule.Header.Destination)
			for _, cc := range cidrChanges {
				risk += cc.RiskContribution
			}

			changes = append(changes, RuleChange{
				ChangeType:       ChangeTypeRuleAdded,
				Severity:         severity,
				ResourceName:     resourceName,
				Description:      fmt.Sprintf("New stateful rule added: action=%s protocol=%s src=%s dst=%s", afterRule.Action, afterRule.Header.Protocol, afterRule.Header.Source, afterRule.Header.Destination),
				After:            key,
				RiskContribution: risk,
			})
			changes = append(changes, cidrChanges...)
			continue
		}

		// Check for action changes.
		if !strings.EqualFold(beforeRule.Action, afterRule.Action) {
			risk := 0.5
			severity := SeverityLow

			if isPermissiveAction(afterRule.Action) && isBlockingAction(beforeRule.Action) {
				risk = 4.0
				severity = SeverityCritical
			} else if isPermissiveAction(afterRule.Action) {
				risk = 2.5
				severity = SeverityHigh
			}

			changes = append(changes, RuleChange{
				ChangeType:       ChangeTypeActionChanged,
				Severity:         severity,
				ResourceName:     resourceName,
				Description:      fmt.Sprintf("Stateful rule action changed for rule (proto=%s src=%s dst=%s)", afterRule.Header.Protocol, afterRule.Header.Source, afterRule.Header.Destination),
				Before:           beforeRule.Action,
				After:            afterRule.Action,
				RiskContribution: risk,
			})
		}

		// Check for CIDR changes on modified rules.
		if beforeRule.Header.Source != afterRule.Header.Source || beforeRule.Header.Destination != afterRule.Header.Destination {
			cidrChanges := d.analyzeCIDR(resourceName, beforeRule.Header.Source, afterRule.Header.Source, afterRule.Header.Destination)
			changes = append(changes, cidrChanges...)
		}
	}

	// Find removed rules.
	for key, beforeRule := range beforeIdx {
		if _, exists := afterIdx[key]; !exists {
			changes = append(changes, RuleChange{
				ChangeType:       ChangeTypeRuleRemoved,
				Severity:         SeverityMedium,
				ResourceName:     resourceName,
				Description:      fmt.Sprintf("Stateful rule removed: action=%s protocol=%s src=%s dst=%s", beforeRule.Action, beforeRule.Header.Protocol, beforeRule.Header.Source, beforeRule.Header.Destination),
				Before:           key,
				RiskContribution: 0.0,
			})
		}
	}

	return changes
}

func (d *Differ) analyzeCIDR(resourceName, beforeSrc, afterSrc, dst string) []RuleChange {
	var changes []RuleChange

	if afterSrc != "" {
		if isAnyAddress(afterSrc) {
			changes = append(changes, RuleChange{
				ChangeType:       ChangeTypeAnySourceAdded,
				Severity:         SeverityCritical,
				ResourceName:     resourceName,
				Description:      "Rule allows traffic from any source (0.0.0.0/0 or ANY)",
				Before:           beforeSrc,
				After:            afterSrc,
				RiskContribution: 4.0,
			})
		} else if beforeSrc != "" && !isAnyAddress(beforeSrc) {
			widened, err := isCIDRWidened(beforeSrc, afterSrc)
			if err == nil && widened {
				changes = append(changes, RuleChange{
					ChangeType:       ChangeTypeCIDRWidened,
					Severity:         SeverityHigh,
					ResourceName:     resourceName,
					Description:      fmt.Sprintf("Source CIDR widened: %s → %s", beforeSrc, afterSrc),
					Before:           beforeSrc,
					After:            afterSrc,
					RiskContribution: 3.0,
				})
			}
		}
	}

	if dst != "" && isAnyAddress(dst) {
		changes = append(changes, RuleChange{
			ChangeType:       ChangeTypeAnySourceAdded,
			Severity:         SeverityHigh,
			ResourceName:     resourceName,
			Description:      "Rule allows traffic to any destination (0.0.0.0/0 or ANY)",
			After:            dst,
			RiskContribution: 2.5,
		})
	}

	return changes
}

func (d *Differ) diffSuricataRules(resourceName, beforeStr, afterStr string) ([]RuleChange, error) {
	var changes []RuleChange

	beforeRules, err := ParseSuricataRules(beforeStr)
	if err != nil && beforeStr != "" {
		return nil, fmt.Errorf("parsing before rules: %w", err)
	}

	afterRules, err := ParseSuricataRules(afterStr)
	if err != nil && afterStr != "" {
		return nil, fmt.Errorf("parsing after rules: %w", err)
	}

	beforeBySID := IndexRulesBySID(beforeRules)
	afterBySID := IndexRulesBySID(afterRules)

	// Check for new and modified rules.
	for sid, afterRule := range afterBySID {
		beforeRule, exists := beforeBySID[sid]
		if !exists {
			risk := 1.0
			if afterRule.Action == "pass" {
				risk = 3.0
			}
			if isAnyAddress(afterRule.SrcIP) || isAnyAddress(afterRule.DstIP) {
				risk += 2.0
			}
			changes = append(changes, RuleChange{
				ChangeType:       ChangeTypeRuleAdded,
				Severity:         suricataActionSeverity(afterRule.Action),
				ResourceName:     resourceName,
				Description:      fmt.Sprintf("New Suricata rule (SID %s): action=%s msg=%q", sid, afterRule.Action, afterRule.Message),
				After:            afterRule.Raw,
				RiskContribution: risk,
			})
			continue
		}

		if SuricataActionChanged(beforeRule, afterRule) {
			risk := 1.0
			severity := SeverityMedium
			if afterRule.Action == "pass" && beforeRule.Action != "pass" {
				risk = 4.0
				severity = SeverityCritical
			} else if afterRule.Action == "alert" && beforeRule.Action == "drop" {
				risk = 2.0
				severity = SeverityHigh
			}
			changes = append(changes, RuleChange{
				ChangeType:       ChangeTypeSuricataAction,
				Severity:         severity,
				ResourceName:     resourceName,
				Description:      fmt.Sprintf("Suricata rule SID %s action changed", sid),
				Before:           beforeRule.Action,
				After:            afterRule.Action,
				RiskContribution: risk,
			})
		}

		// Check CIDR changes within Suricata rules.
		if beforeRule.SrcIP != afterRule.SrcIP {
			if isAnyAddress(afterRule.SrcIP) {
				changes = append(changes, RuleChange{
					ChangeType:       ChangeTypeAnySourceAdded,
					Severity:         SeverityCritical,
					ResourceName:     resourceName,
					Description:      fmt.Sprintf("Suricata rule SID %s source widened to ANY", sid),
					Before:           beforeRule.SrcIP,
					After:            afterRule.SrcIP,
					RiskContribution: 4.0,
				})
			} else {
				widened, err := isCIDRWidened(beforeRule.SrcIP, afterRule.SrcIP)
				if err == nil && widened {
					changes = append(changes, RuleChange{
						ChangeType:       ChangeTypeCIDRWidened,
						Severity:         SeverityHigh,
						ResourceName:     resourceName,
						Description:      fmt.Sprintf("Suricata rule SID %s source CIDR widened", sid),
						Before:           beforeRule.SrcIP,
						After:            afterRule.SrcIP,
						RiskContribution: 3.0,
					})
				}
			}
		}
	}

	// Check for removed rules.
	for sid, beforeRule := range beforeBySID {
		if _, exists := afterBySID[sid]; !exists {
			changes = append(changes, RuleChange{
				ChangeType:       ChangeTypeRuleRemoved,
				Severity:         SeverityMedium,
				ResourceName:     resourceName,
				Description:      fmt.Sprintf("Suricata rule SID %s removed: action=%s msg=%q", sid, beforeRule.Action, beforeRule.Message),
				Before:           beforeRule.Raw,
				RiskContribution: 0.0,
			})
		}
	}

	return changes, nil
}

func (d *Differ) diffRulesSourceList(resourceName string, before, after *RulesSourceList) []RuleChange {
	var changes []RuleChange

	if after == nil {
		return changes
	}

	var beforeTargets map[string]bool
	if before != nil {
		beforeTargets = make(map[string]bool, len(before.Targets))
		for _, t := range before.Targets {
			beforeTargets[t] = true
		}
	}

	for _, target := range after.Targets {
		if beforeTargets != nil && beforeTargets[target] {
			continue
		}

		isWildcard := strings.HasPrefix(target, "*.")
		risk := 1.5
		severity := SeverityMedium
		ct := ChangeTypeFQDNAdded

		if isWildcard {
			risk = 3.0
			severity = SeverityHigh
			ct = ChangeTypeFQDNWildcard
		}

		changes = append(changes, RuleChange{
			ChangeType:       ct,
			Severity:         severity,
			ResourceName:     resourceName,
			Description:      fmt.Sprintf("FQDN target added: %s (type=%s)", target, after.GeneratedRulesType),
			After:            target,
			RiskContribution: risk,
		})
	}

	return changes
}

// statefulRuleKey produces a canonical string key for a stateful rule for indexing purposes.
func statefulRuleKey(r StatefulRule) string {
	return fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s",
		strings.ToUpper(r.Action),
		strings.ToUpper(r.Header.Protocol),
		r.Header.Source,
		r.Header.SourcePort,
		r.Header.Direction,
		r.Header.Destination,
		r.Header.DestinationPort,
	)
}

// isAnyAddress returns true if the given IP/CIDR string represents "any" traffic.
func isAnyAddress(addr string) bool {
	upper := strings.ToUpper(addr)
	if upper == "ANY" || upper == "$ANY" {
		return true
	}
	_, ipNet, err := net.ParseCIDR(addr)
	if err != nil {
		return false
	}
	ones, _ := ipNet.Mask.Size()
	return ones == 0
}

// isCIDRWidened returns true if after encompasses a strictly larger address space than before.
// Both must be parseable CIDR strings.
func isCIDRWidened(before, after string) (bool, error) {
	_, beforeNet, err := net.ParseCIDR(before)
	if err != nil {
		return false, fmt.Errorf("parsing before CIDR %q: %w", before, err)
	}

	_, afterNet, err := net.ParseCIDR(after)
	if err != nil {
		return false, fmt.Errorf("parsing after CIDR %q: %w", after, err)
	}

	beforeOnes, _ := beforeNet.Mask.Size()
	afterOnes, _ := afterNet.Mask.Size()

	// A smaller prefix length means a larger network.
	if afterOnes >= beforeOnes {
		return false, nil
	}

	// Confirm that the after network contains the before network (not just a different /smaller block).
	return afterNet.Contains(beforeNet.IP), nil
}

// isPermissiveAction returns true for actions that allow traffic through.
func isPermissiveAction(action string) bool {
	upper := strings.ToUpper(action)
	return upper == "PASS" || upper == "ALLOW"
}

// isBlockingAction returns true for actions that block traffic.
func isBlockingAction(action string) bool {
	upper := strings.ToUpper(action)
	return upper == "DROP" || upper == "REJECT" || upper == "BLOCK"
}

// suricataActionSeverity maps a Suricata action to a severity level.
func suricataActionSeverity(action string) Severity {
	switch strings.ToLower(action) {
	case "pass":
		return SeverityCritical
	case "drop", "reject":
		return SeverityLow
	case "alert":
		return SeverityMedium
	default:
		return SeverityInfo
	}
}
