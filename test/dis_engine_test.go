package test

import (
	"fmt"
	"testing"

	"github.com/yasin-wu/dsi_engine/consts"
	"github.com/yasin-wu/dsi_engine/dsi_engine"
	"github.com/yasin-wu/dsi_engine/policy"
	"github.com/yasin-wu/dsi_engine/rule"

	"github.com/davecgh/go-spew/spew"
	"github.com/yasin-wu/utils/file_parser"
)

func TestDsiEngine(t *testing.T) {
	err := rule.InitRule()
	if err != nil {
		fmt.Println(err)
		return
	}
	rulesMap := rule.RulesMap
	sensitiveData := &policy.SensitiveData{
		FilePath: "./sample/test.docx",
		FileName: "test.docx",
	}
	parser, err := file_parser.New("http://47.108.155.25:9998", nil, nil)
	if err != nil {
		t.Error(err)
		return
	}
	filePath := "/Users/yasin/GolandProjects/yasin-wu/dsi_engine/sample/test.docx"
	f, err := parser.Parser(filePath, true)
	if err != nil {
		t.Errorf("fileParse.FileParse err :%v", err)
		return
	}
	sensitiveData.FileSize = f.Size
	sensitiveData.Content = f.Content
	rule1 := &policy.Rule{
		Id:               "1",
		Name:             "正则匹配:地址信息",
		Type:             consts.Regexp,
		Regexp:           rulesMap["ADDRESS"].(map[string]interface{})["rule"].(string),
		ForWardThreshold: 1,
	}
	rule2 := &policy.Rule{
		Id:               "2",
		Name:             "模糊关键字:我们",
		Type:             consts.FuzzyWords,
		ForWardKeyList:   []string{"我们"},
		CharacterSpace:   5,
		ForWardThreshold: 1,
	}
	policy1 := &policy.Policy{
		Id:        "1",
		Operators: []int{consts.And},
		Rules:     []*policy.Rule{rule1, rule2},
	}
	policy2 := &policy.Policy{
		Id:        "2",
		Operators: []int{consts.Or},
		Rules:     []*policy.Rule{rule1, rule2},
	}
	var policies []*policy.Policy
	policies = append(policies, policy1)
	policies = append(policies, policy2)
	engine, err := dsi_engine.New(sensitiveData)
	if err != nil {
		t.Error(err.Error())
		return
	}
	for i, policyInfo := range policies {
		alarm, err := engine.Run(policyInfo)
		if err != nil {
			t.Errorf("run err:%s", err.Error())
			continue
		}
		alarm.Id = fmt.Sprintf("%d", i)
		spew.Dump(alarm)
		fmt.Println("============================")
	}
}
