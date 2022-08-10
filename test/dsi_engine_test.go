package test

import (
	"encoding/json"
	"fmt"
	"log"
	"testing"

	parser2 "github.com/yasin-wu/dsi_engine/v2/pkg/parser"

	rule2 "github.com/yasin-wu/dsi_engine/v2/pkg/rule"

	"github.com/yasin-wu/dsi_engine/v2/engine"
	"github.com/yasin-wu/dsi_engine/v2/pkg/enum"

	"github.com/yasin-wu/dsi_engine/v2/pkg/entity"
)

func TestDsiEngine(t *testing.T) {
	rule, err := rule2.New()
	if err != nil {
		log.Fatal(err)
	}
	rulesMap := rule.RuleMap
	sensitiveData := &entity.SensitiveData{
		FilePath: "../sample/test.docx",
	}
	parser(sensitiveData)
	sensitiveData.Policies = handlePolicies(rulesMap)
	engine := engine.New()
	alarms, err := engine.Run(sensitiveData)
	if err != nil {
		log.Fatal(err)
	}
	buff, _ := json.MarshalIndent(alarms, "", "\t")
	fmt.Println(string(buff))
}

func parser(sensitiveData *entity.SensitiveData) {
	parser := parser2.New("http://localhost:9998")
	f, err := parser.Parse(sensitiveData.FilePath, true)
	if err != nil {
		log.Fatal(err)
	}
	sensitiveData.FileName = f.Name
	sensitiveData.FileType = f.FileType
	sensitiveData.FileSize = f.Size
	sensitiveData.Content = f.Content
}

func handlePolicies(rulesMap map[string]rule2.R) []*entity.Policy {
	rule1 := entity.Rule{
		ID:               "1",
		Name:             "正则匹配:地址信息",
		Type:             enum.RegexpRuletype,
		Regexp:           rulesMap["ADDRESS"].Regexp,
		ForWardThreshold: 1,
	}
	rule2 := entity.Rule{
		ID:               "2",
		Name:             "模糊关键字:我们",
		Type:             enum.FuzzywordsRuletype,
		ForWardKeyList:   []string{"我们"},
		CharacterSpace:   5,
		ForWardThreshold: 1,
	}
	policy1 := &entity.Policy{
		ID:        "1",
		Operators: []enum.Operator{enum.AndOperator},
		Rules:     []entity.Rule{rule1, rule2},
	}
	policy2 := &entity.Policy{
		ID:        "2",
		Operators: []enum.Operator{enum.OrOperator},
		Rules:     []entity.Rule{rule1, rule2},
	}
	var policies []*entity.Policy
	policies = append(policies, policy1, policy2)
	return policies
}
