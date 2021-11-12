package test

import (
	"fmt"
	"testing"

	"github.com/yasin-wu/dsi_engine/v2/regexp_engine"
	"github.com/yasin-wu/dsi_engine/v2/rule"
)

func TestRegexpEngine(t *testing.T) {
	err := rule.InitRule()
	if err != nil {
		fmt.Println(err)
		return
	}
	err = rule.AddRule("../scripts/rules.json")
	if err != nil {
		t.Error(err.Error())
		return
	}
	rulesMap := rule.RulesMap
	inputData := "My name is Bob;" +
		"电话号码:18108279331;" +
		"测试IPV6地址正则:fe80::ec61:c1d1:9827:82be%13;" +
		"地址信息:四川省成都市武侯区府城大道天府新谷6号楼607室."
	regexp1 := &regexp_engine.Regexp{
		Id:     1,
		Regexp: rulesMap["IPV6"].(map[string]interface{})["rule"].(string),
	}
	regexp2 := &regexp_engine.Regexp{
		Id:     2,
		Regexp: rulesMap["USER_NAME"].(map[string]interface{})["rule"].(string),
	}
	regexp3 := &regexp_engine.Regexp{
		Id:     3,
		Regexp: rulesMap["PHONE_NUMBER"].(map[string]interface{})["rule"].(string),
	}
	regexp4 := &regexp_engine.Regexp{
		Id:     4,
		Regexp: rulesMap["ADDRESS"].(map[string]interface{})["rule"].(string),
	}
	engine, err := regexp_engine.New(regexp1, regexp2, regexp3, regexp4)
	if err != nil {
		t.Error(err.Error())
		return
	}
	matches, err := engine.Run(inputData)
	if err != nil {
		t.Error(err.Error())
		return
	}
	for _, m := range matches {
		t.Logf("命中正则id:%d;命中内容:%s", m.Id, m.InputData[m.From:m.To])
	}
}
