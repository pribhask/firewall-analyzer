package terraform

import (
	"fmt"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// Parser parses Terraform HCL files to extract AWS Network Firewall resources.
type Parser struct{}

// NewParser creates a new HCL parser.
func NewParser() *Parser {
	return &Parser{}
}

// ParseFile parses the raw bytes of a Terraform file and extracts all
// aws_networkfirewall_rule_group resource blocks.
func (p *Parser) ParseFile(filename string, src []byte) (*RuleGroupFile, error) {
	file, diags := hclsyntax.ParseConfig(src, filename, hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		return nil, fmt.Errorf("parsing HCL: %s", diags.Error())
	}

	body, ok := file.Body.(*hclsyntax.Body)
	if !ok {
		return nil, fmt.Errorf("unexpected body type")
	}

	result := &RuleGroupFile{}

	for _, block := range body.Blocks {
		if block.Type != "resource" {
			continue
		}
		if len(block.Labels) < 2 {
			continue
		}
		if block.Labels[0] != "aws_networkfirewall_rule_group" {
			continue
		}

		resourceName := block.Labels[1]
		rg, err := p.parseRuleGroupBlock(resourceName, block.Body)
		if err != nil {
			return nil, fmt.Errorf("parsing rule group %q: %w", resourceName, err)
		}

		result.RuleGroups = append(result.RuleGroups, *rg)
	}

	return result, nil
}

func (p *Parser) parseRuleGroupBlock(name string, body *hclsyntax.Body) (*RuleGroup, error) {
	rg := &RuleGroup{
		Name: name,
		Tags: make(map[string]string),
	}

	for attrName, attr := range body.Attributes {
		val, diags := attr.Expr.Value(nil)
		if diags.HasErrors() {
			// Attributes with variable references cannot be statically evaluated; skip them.
			continue
		}

		switch attrName {
		case "description":
			if val.Type() == cty.String && !val.IsNull() {
				rg.Description = val.AsString()
			}
		case "capacity":
			if val.Type() == cty.Number && !val.IsNull() {
				bf := val.AsBigFloat()
				i, _ := bf.Int64()
				rg.Capacity = i
			}
		case "type":
			if val.Type() == cty.String && !val.IsNull() {
				rg.Type = val.AsString()
			}
		case "tags":
			if val.Type().IsObjectType() && !val.IsNull() {
				for k, v := range val.AsValueMap() {
					if v.Type() == cty.String && !v.IsNull() {
						rg.Tags[k] = v.AsString()
					}
				}
			}
		}
	}

	for _, block := range body.Blocks {
		if block.Type == "rule_group" {
			config, err := p.parseRuleGroupConfigBlock(block.Body)
			if err != nil {
				return nil, fmt.Errorf("parsing rule_group config block: %w", err)
			}
			rg.RuleGroupConfig = *config
		}
	}

	return rg, nil
}

func (p *Parser) parseRuleGroupConfigBlock(body *hclsyntax.Body) (*RuleGroupConfig, error) {
	config := &RuleGroupConfig{}

	for _, block := range body.Blocks {
		switch block.Type {
		case "rules_source":
			rs, err := p.parseRulesSource(block.Body)
			if err != nil {
				return nil, fmt.Errorf("parsing rules_source: %w", err)
			}
			config.RulesSource = *rs

		case "stateful_rule_options":
			for attrName, attr := range block.Body.Attributes {
				if attrName == "rule_order" {
					val, diags := attr.Expr.Value(nil)
					if !diags.HasErrors() && val.Type() == cty.String && !val.IsNull() {
						config.StatefulRuleOptions.RuleOrder = val.AsString()
					}
				}
			}
		}
	}

	return config, nil
}

func (p *Parser) parseRulesSource(body *hclsyntax.Body) (*RulesSource, error) {
	rs := &RulesSource{}

	for attrName, attr := range body.Attributes {
		if attrName == "rules_string" {
			val, diags := attr.Expr.Value(nil)
			if !diags.HasErrors() && val.Type() == cty.String && !val.IsNull() {
				rs.RulesString = val.AsString()
			}
		}
	}

	for _, block := range body.Blocks {
		switch block.Type {
		case "stateful_rule":
			sr, err := p.parseStatefulRule(block.Body)
			if err != nil {
				return nil, fmt.Errorf("parsing stateful_rule: %w", err)
			}
			rs.StatefulRules = append(rs.StatefulRules, *sr)

		case "rules_source_list":
			rsl, err := p.parseRulesSourceList(block.Body)
			if err != nil {
				return nil, fmt.Errorf("parsing rules_source_list: %w", err)
			}
			rs.RulesSourceList = rsl
		}
	}

	return rs, nil
}

func (p *Parser) parseStatefulRule(body *hclsyntax.Body) (*StatefulRule, error) {
	sr := &StatefulRule{}

	for attrName, attr := range body.Attributes {
		if attrName == "action" {
			val, diags := attr.Expr.Value(nil)
			if !diags.HasErrors() && val.Type() == cty.String && !val.IsNull() {
				sr.Action = val.AsString()
			}
		}
	}

	for _, block := range body.Blocks {
		switch block.Type {
		case "header":
			header, err := p.parseStatefulRuleHeader(block.Body)
			if err != nil {
				return nil, fmt.Errorf("parsing header: %w", err)
			}
			sr.Header = *header

		case "rule_option":
			opt, err := p.parseRuleOption(block.Body)
			if err != nil {
				return nil, fmt.Errorf("parsing rule_option: %w", err)
			}
			sr.Options = append(sr.Options, *opt)
		}
	}

	return sr, nil
}

func (p *Parser) parseStatefulRuleHeader(body *hclsyntax.Body) (*StatefulRuleHeader, error) {
	header := &StatefulRuleHeader{}

	stringAttrs := map[string]*string{
		"protocol":         &header.Protocol,
		"source":           &header.Source,
		"source_port":      &header.SourcePort,
		"direction":        &header.Direction,
		"destination":      &header.Destination,
		"destination_port": &header.DestinationPort,
	}

	for attrName, attr := range body.Attributes {
		if ptr, ok := stringAttrs[attrName]; ok {
			val, diags := attr.Expr.Value(nil)
			if !diags.HasErrors() && val.Type() == cty.String && !val.IsNull() {
				*ptr = val.AsString()
			}
		}
	}

	return header, nil
}

func (p *Parser) parseRuleOption(body *hclsyntax.Body) (*RuleOption, error) {
	opt := &RuleOption{}

	for attrName, attr := range body.Attributes {
		val, diags := attr.Expr.Value(nil)
		if diags.HasErrors() {
			continue
		}

		switch attrName {
		case "keyword":
			if val.Type() == cty.String && !val.IsNull() {
				opt.Keyword = val.AsString()
			}
		case "settings":
			if val.Type().IsListType() || val.Type().IsTupleType() {
				for it := val.ElementIterator(); it.Next(); {
					_, v := it.Element()
					if v.Type() == cty.String && !v.IsNull() {
						opt.Settings = append(opt.Settings, v.AsString())
					}
				}
			}
		}
	}

	return opt, nil
}

func (p *Parser) parseRulesSourceList(body *hclsyntax.Body) (*RulesSourceList, error) {
	rsl := &RulesSourceList{}

	for attrName, attr := range body.Attributes {
		val, diags := attr.Expr.Value(nil)
		if diags.HasErrors() {
			continue
		}

		switch attrName {
		case "generated_rules_type":
			if val.Type() == cty.String && !val.IsNull() {
				rsl.GeneratedRulesType = val.AsString()
			}
		case "target_types":
			if val.Type().IsListType() || val.Type().IsTupleType() {
				for it := val.ElementIterator(); it.Next(); {
					_, v := it.Element()
					if v.Type() == cty.String && !v.IsNull() {
						rsl.TargetTypes = append(rsl.TargetTypes, v.AsString())
					}
				}
			}
		case "targets":
			if val.Type().IsListType() || val.Type().IsTupleType() {
				for it := val.ElementIterator(); it.Next(); {
					_, v := it.Element()
					if v.Type() == cty.String && !v.IsNull() {
						rsl.Targets = append(rsl.Targets, v.AsString())
					}
				}
			}
		}
	}

	return rsl, nil
}
