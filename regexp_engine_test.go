package dsi_engine

import (
	"fmt"
	"log"
	"testing"

	"github.com/yasin-wu/dsi_engine/v2/consts"

	"github.com/yasin-wu/dsi_engine/v2/regexp"
	rule2 "github.com/yasin-wu/dsi_engine/v2/rule"
)

func TestRegexpEngine(t *testing.T) {
	rule, err := rule2.New()
	if err != nil {
		log.Fatal(err)
	}
	var m = make(map[string]rule2.R)
	m["TEST"] = rule2.R{
		Regexp: "测试",
		Desc:   "测试",
	}
	err = rule.Add("./conf/rules.json", m)
	if err != nil {
		log.Fatal(err)
	}
	rulesMap := rule.RuleMap
	inputData := "My name is Bob;电话号码:18108379230;测试IPV6地址正则:fe80::ec61:c1d1:9827:82be%13;地址信息:四川省成都市武侯区府城大道天府新谷8号楼1007室."
	regexp1 := &regexp.Regexp{
		Id:     1,
		Regexp: rulesMap["IPV6"].Regexp,
	}
	regexp2 := &regexp.Regexp{
		Id:     2,
		Regexp: rulesMap["USER_NAME"].Regexp,
	}
	regexp3 := &regexp.Regexp{
		Id:     3,
		Regexp: rulesMap["PHONE_NUMBER"].Regexp,
	}
	regexp4 := &regexp.Regexp{
		Id:     4,
		Regexp: rulesMap["ADDRESS"].Regexp,
	}
	regexp5 := &regexp.Regexp{
		Id:     5,
		Regexp: rulesMap["TEST"].Regexp,
	}
	engine, err := regexp.New(regexp1, regexp2, regexp3, regexp4, regexp5)
	if err != nil {
		log.Fatal(err)
	}
	matches, err := engine.Run(inputData)
	if err != nil {
		log.Fatal(err)
	}
	for _, m := range matches {
		fmt.Printf("命中规则ID:%s%v%s;命中内容:%s%v%s\n",
			consts.Red, m.Id, consts.Reset, consts.Red, m.InputData[m.From:m.To], consts.Reset)
	}
}
