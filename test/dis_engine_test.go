package test

import (
	"fmt"
	"testing"

	"github.com/yasin-wu/dsi_engine/v2/enum"

	"github.com/apolloconfig/agollo/v4"
	"github.com/apolloconfig/agollo/v4/env/config"

	"github.com/davecgh/go-spew/spew"

	"github.com/yasin-wu/dsi_engine/v2/dsi_engine"
	"github.com/yasin-wu/dsi_engine/v2/policy"
	rule2 "github.com/yasin-wu/dsi_engine/v2/rule"

	"github.com/yasin-wu/utils/file_parser"
)

func TestDsiEngine(t *testing.T) {
	rule, err := rule2.New()
	if err != nil {
		fmt.Println(err)
		return
	}
	rulesMap := rule.RuleMap
	sensitiveData := &policy.SensitiveData{
		FilePath: "../sample/test.docx",
	}
	parser(sensitiveData)
	sensitiveData.Policies = handlePolicies(rulesMap)
	engine, err := dsi_engine.New(sensitiveData)
	if err != nil {
		t.Error(err.Error())
		return
	}
	alarms, err := engine.Run()
	spew.Dump(err)
	spew.Dump(alarms)
}

func parser(sensitiveData *policy.SensitiveData) {
	client, _ := agollo.StartWithConfig(func() (*config.AppConfig, error) {
		return apolloConf, nil
	})
	fmt.Println("初始化Apollo配置成功")
	cache := client.GetConfigCache(apolloConf.NamespaceName)
	url, _ := cache.Get("tika.url")
	parser, err := file_parser.New(url.(string), nil, nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	f, err := parser.Parser(sensitiveData.FilePath, true)
	if err != nil {
		fmt.Println("fileParse.FileParse err :" + err.Error())
		return
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
