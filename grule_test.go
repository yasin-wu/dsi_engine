package dlp

import (
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
	filePolicy := &FilePolicy{
		FilePath: "./sample/test.docx",
		FileName: "test.docx",
	}
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
	policyContent1 := &RuleContent{
		RuleType:         RuleTypeRegexp,
		Regexp:           AddressReg,
		ForWardThreshold: 1,
	}
	policyContent2 := &RuleContent{
		RuleType:         RuleTypeFuzzyWords,
		ForWardKeyList:   []string{"我们"},
		CharacterSpace:   5,
		ForWardThreshold: 1,
	}
	policy1 := &PolicyInfo{
		PolicyId:  "1",
		Operators: []int{RuleAnd},
	}
	policy2 := &PolicyInfo{
		PolicyId:  "2",
		Operators: []int{RuleOr},
	}
	policy1.RuleContents = append(policy1.RuleContents, policyContent1, policyContent2)
	policy2.RuleContents = append(policy2.RuleContents, policyContent1, policyContent2)
	filePolicy.PolicyInfos = append(filePolicy.PolicyInfos, policy1)
	filePolicy.PolicyInfos = append(filePolicy.PolicyInfos, policy2)
	for _, policyInfo := range filePolicy.PolicyInfos {
		grule := &GRule{
			FilePolicy: filePolicy,
			PolicyInfo: policyInfo,
		}
		err = grule.RunFileCheck()
		if err != nil {
			t.Errorf("grule.RunFileCheck err:%s", err.Error())
			continue
		}
		spew.Dump(grule.PolicyAlarm)
	}
}
