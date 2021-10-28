package test

import (
	"fmt"
	"testing"

	"github.com/yasin-wu/dsi_engine/consts"
	grule2 "github.com/yasin-wu/dsi_engine/grule"
	"github.com/yasin-wu/dsi_engine/policy"
	"github.com/yasin-wu/dsi_engine/rule"

	"github.com/davecgh/go-spew/spew"
	"github.com/yasin-wu/utils/file_parser"
)

/**
 * @author: yasin
 * @date: 2020/7/2 16:20
 * @description：文件策略匹配
 */
func TestGRule(t *testing.T) {
	err := rule.InitRule()
	if err != nil {
		fmt.Println(err)
		return
	}
	rm := rule.RulesMap
	filePolicy := &policy.FilePolicy{
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
	filePolicy.FileSize = f.Size
	filePolicy.Content = f.Content
	policyContent1 := &policy.RuleContent{
		RuleId:           "1",
		RuleName:         "正则匹配:地址信息",
		RuleType:         consts.RuleTypeRegexp,
		Regexp:           rm["ADDRESS"].(map[string]interface{})["rule"].(string),
		ForWardThreshold: 1,
	}
	policyContent2 := &policy.RuleContent{
		RuleId:           "2",
		RuleName:         "模糊关键字:我们",
		RuleType:         consts.RuleTypeFuzzyWords,
		ForWardKeyList:   []string{"我们"},
		CharacterSpace:   5,
		ForWardThreshold: 1,
	}
	policy1 := &policy.PolicyInfo{
		PolicyId:     "1",
		Operators:    []int{consts.RuleAnd},
		RuleContents: []*policy.RuleContent{policyContent1, policyContent2},
	}
	policy2 := &policy.PolicyInfo{
		PolicyId:     "2",
		Operators:    []int{consts.RuleOr},
		RuleContents: []*policy.RuleContent{policyContent1, policyContent2},
	}
	filePolicy.PolicyInfos = append(filePolicy.PolicyInfos, policy1)
	filePolicy.PolicyInfos = append(filePolicy.PolicyInfos, policy2)
	for i, policyInfo := range filePolicy.PolicyInfos {
		grule, err := grule2.New(filePolicy, policyInfo)
		if err != nil {
			t.Error(err.Error())
			continue
		}
		err = grule.RunCheckFile()
		if err != nil {
			t.Errorf("grule.RunFileCheck err:%s", err.Error())
			continue
		}
		grule.PolicyAlarm.Id = fmt.Sprintf("%d", i)
		spew.Dump(grule.PolicyAlarm)
	}
}
