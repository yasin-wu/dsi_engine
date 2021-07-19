package test

import (
	"fmt"
	"testing"

	gohs2 "github.com/yasin-wu/dlp/gohs"
	"github.com/yasin-wu/dlp/rule"
)

func TestGohs(t *testing.T) {
	err := rule.InitRule()
	if err != nil {
		fmt.Println(err)
		return
	}
	err = rule.AddRule("../scripts/rules.json")
	rm := rule.RulesMap
	inputData := "My name is Bob;" +
		"电话号码:18108279331;" +
		"测试IPV6地址正则:fe80::ec61:c1d1:9827:82be%13;" +
		"地址信息:四川省成都市武侯区府城大道天府新谷6号楼607室."
	regexp1 := &gohs2.Regexp{
		Id:     1,
		Regexp: rm["IPV6"].(map[string]interface{})["rule"].(string),
	}
	regexp2 := &gohs2.Regexp{
		Id:     2,
		Regexp: rm["USER_NAME"].(map[string]interface{})["rule"].(string),
	}
	regexp3 := &gohs2.Regexp{
		Id:     3,
		Regexp: rm["PHONE_NUMBER"].(map[string]interface{})["rule"].(string),
	}
	regexp4 := &gohs2.Regexp{
		Id:     4,
		Regexp: rm["ADDRESS"].(map[string]interface{})["rule"].(string),
	}
	gohs, err := gohs2.New(regexp1, regexp2, regexp3, regexp4)
	if err != nil {
		t.Error(err.Error())
		return
	}
	matches, err := gohs.Run(inputData)
	if err != nil {
		t.Error(err.Error())
		return
	}
	for _, m := range matches {
		t.Logf("命中正则id:%d;命中内容:%s", m.Id, m.InputData[m.From:m.To])
	}
}
