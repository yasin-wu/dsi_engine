package test

import (
	"encoding/json"
	"fmt"
	"log"
	"testing"

	"github.com/yasin-wu/dsi_engine/v2/enum"

	"github.com/yasin-wu/dsi_engine/v2/dsi_engine"
	"github.com/yasin-wu/dsi_engine/v2/policy"
	rule2 "github.com/yasin-wu/dsi_engine/v2/rule"

	"github.com/yasin-wu/utils/file_parser"
)

func init() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
}

func TestDsiEngine(t *testing.T) {
	rule, err := rule2.New()
	if err != nil {
		log.Fatal(err)
	}
	rulesMap := rule.RuleMap
	sensitiveData := &policy.SensitiveData{
		FilePath: "../sample/test.docx",
	}
	parser(sensitiveData)
	sensitiveData.Policies = handlePolicies(rulesMap)
	engine := dsi_engine.New()
	alarms, err := engine.Run(sensitiveData)
	if err != nil {
		log.Fatal(err)
	}
	buff, _ := json.MarshalIndent(alarms, "", "\t")
	fmt.Println(string(buff))
}

func parser(sensitiveData *policy.SensitiveData) {
	parser := file_parser.New("http://47.108.155.25:9998")
	f, err := parser.Parse(sensitiveData.FilePath, true)
	if err != nil {
		log.Fatal(err)
	}
	sensitiveData.FileName = f.Name
	sensitiveData.FileType = f.FileType
	sensitiveData.FileSize = f.Size
	sensitiveData.Content = f.Content
}

func handlePolicies(rulesMap map[string]rule2.R) []*policy.Policy {
	rule1 := &policy.Rule{
		Id:               "1",
		Name:             "正则匹配:地址信息",
		Type:             enum.REGEXP_RULETYPE,
		Regexp:           rulesMap["ADDRESS"].Regexp,
		ForWardThreshold: 1,
	}
	rule2 := &policy.Rule{
		Id:               "2",
		Name:             "模糊关键字:我们",
		Type:             enum.FUZZYWORDS_RULETYPE,
		ForWardKeyList:   []string{"我们"},
		CharacterSpace:   5,
		ForWardThreshold: 1,
	}
	policy1 := &policy.Policy{
		Id:        "1",
		Operators: []enum.Operator{enum.AND_OPERATOR},
		Rules:     []*policy.Rule{rule1, rule2},
	}
	policy2 := &policy.Policy{
		Id:        "2",
		Operators: []enum.Operator{enum.OR_OPERATOR},
		Rules:     []*policy.Rule{rule1, rule2},
	}
	var policies []*policy.Policy
	policies = append(policies, policy1, policy2)
	return policies
}
