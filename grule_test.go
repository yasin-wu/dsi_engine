package dlp

import (
	"github.com/davecgh/go-spew/spew"
	"github.com/yasin-wu/fileparser"
	"os"
	"testing"
)

/**
 * @author: yasin
 * @date: 2020/7/2 16:20
 * @description：文件策略匹配
 */
func TestGRule_RunFileCheck(t *testing.T) {
	filePolicy := &FilePolicy{}
	filePolicy.FilePath = "./sample/test.docx"
	filePolicy.FileName = "test.docx"
	file, err := os.Open(filePolicy.FilePath)
	if err != nil {
		t.Errorf("os.open err:%v", err.Error())
		return
	}

	cfg := fileparser.Config{
		TikaUrl: "http://192.168.131.135:9998",
	}
	c := fileparser.NewClient(cfg)
	f, err := c.ParseFile(true, file)
	if err != nil {
		t.Errorf("fileParse.FileParse err :%v", err)
		return
	}
	filePolicy.FileSize = f.Size
	filePolicy.Content = f.Content
	policy1 := &PolicyInfo{}
	policy1.PolicyId = "1"
	policy1.Operators = []int{RuleAnd}
	policyContent1 := &RuleContent{}
	policyContent1.RuleType = RuleTypeRegexp
	policyContent1.Regexp = AddressReg
	policyContent1.ForWardThreshold = 1

	policy2 := &PolicyInfo{}
	policy2.PolicyId = "2"
	policy2.Operators = []int{RuleOr}
	policyContent2 := &RuleContent{}
	policyContent2.RuleType = RuleTypeFuzzyWords
	policyContent2.ForWardKeyList = []string{"我们"}
	policyContent2.CharacterSpace = 5
	policyContent2.ForWardThreshold = 1

	policy1.RuleContents = append(policy1.RuleContents, policyContent1, policyContent2)
	policy2.RuleContents = append(policy2.RuleContents, policyContent1, policyContent2)
	filePolicy.PolicyInfos = append(filePolicy.PolicyInfos, policy1)
	filePolicy.PolicyInfos = append(filePolicy.PolicyInfos, policy2)

	for i := 0; i < len(filePolicy.PolicyInfos); i++ {
		grule := &GRule{}
		grule.FilePolicy = filePolicy
		grule.PolicyIndex = int64(i)
		grule.RunFileCheck()
		spew.Dump(grule.PolicyAlarm)
	}
}
