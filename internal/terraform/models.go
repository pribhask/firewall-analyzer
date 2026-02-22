package terraform

// RuleGroupFile represents all aws_networkfirewall_rule_group resources in a single Terraform file.
type RuleGroupFile struct {
	RuleGroups []RuleGroup
}

// RuleGroup maps to the aws_networkfirewall_rule_group Terraform resource.
type RuleGroup struct {
	Name        string   // Terraform resource label (e.g., "my_rule_group")
	Description string
	Capacity    int64
	Type        string // STATEFUL or STATELESS
	Tags        map[string]string
	RuleGroupConfig RuleGroupConfig
}

// RuleGroupConfig maps to the nested rule_group block inside the resource.
type RuleGroupConfig struct {
	RulesSource      RulesSource
	StatefulRuleOptions StatefulRuleOptions
}

// RulesSource holds all rule source types (only one is typically populated).
type RulesSource struct {
	RulesString     string          // Raw Suricata rule string
	StatefulRules   []StatefulRule
	RulesSourceList *RulesSourceList
}

// StatefulRule maps to the stateful_rule block.
type StatefulRule struct {
	Action string // ALERT, DROP, PASS, REJECT
	Header StatefulRuleHeader
	Options []RuleOption
}

// StatefulRuleHeader defines the 5-tuple for stateful rules.
type StatefulRuleHeader struct {
	Protocol        string
	Source          string
	SourcePort      string
	Direction       string
	Destination     string
	DestinationPort string
}

// RuleOption is a key-value pair within a stateful_rule's rule_option block.
type RuleOption struct {
	Keyword  string
	Settings []string
}

// RulesSourceList maps to the rules_source_list block (FQDN-based filtering).
type RulesSourceList struct {
	GeneratedRulesType string // ALLOWLIST or DENYLIST
	TargetTypes        []string
	Targets            []string
}

// StatefulRuleOptions configures ordering for stateful rules.
type StatefulRuleOptions struct {
	RuleOrder string // STRICT_ORDER or DEFAULT_ACTION_ORDER
}
