package dlp

import (
	"fmt"
	"github.com/yasin-wu/dlp/consts"
	grule2 "github.com/yasin-wu/dlp/grule"
	"github.com/yasin-wu/dlp/policy"
	"github.com/yasin-wu/dlp/rule"
	"os"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/yasin-wu/fileparser"
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
	file, err := os.Open(filePolicy.FilePath)
	if err != nil {
		t.Errorf("os.open err:%v", err.Error())
		return
	}
	cfg := fileparser.Config{
		TikaUrl: "http://47.108.155.25:9998",
	}
	c := fileparser.NewClient(cfg)
	f, err := c.ParseFile(true, file)
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
		grule := grule2.New(filePolicy, policyInfo)
		err = grule.RunCheckFile()
		if err != nil {
			t.Errorf("grule.RunFileCheck err:%s", err.Error())
			continue
		}
		grule.PolicyAlarm.Id = fmt.Sprintf("%d", i)
		spew.Dump(grule.PolicyAlarm)
	}
}
