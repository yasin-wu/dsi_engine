package dlp

import (
	"fmt"
	gohs2 "github.com/yasin-wu/dlp/gohs"
	"github.com/yasin-wu/dlp/rule"
	"testing"

	"github.com/flier/gohs/hyperscan"
)

func TestGohs(t *testing.T) {
	err := rule.InitRule()
	if err != nil {
		fmt.Println(err)
		return
	}
	rm := rule.RulesMap
	inputData := "My name is Bob;" +
		"电话号码:18108279331;" +
		"测试IPV6地址正则:fe80::ec61:c1d1:9827:82be%13;" +
		"地址信息:四川省成都市武侯区府城大道天府新谷6号楼607室."
	var patterns []*hyperscan.Pattern
	pattern1 := hyperscan.NewPattern(rm["IPV6"].(map[string]interface{})["rule"].(string), hyperscan.SomLeftMost|hyperscan.Utf8Mode)
	pattern1.Id = 1
	pattern2 := hyperscan.NewPattern("Bob", hyperscan.SomLeftMost|hyperscan.Utf8Mode)
	pattern2.Id = 2
	pattern3 := hyperscan.NewPattern(rm["PHONE_NUMBER"].(map[string]interface{})["rule"].(string), hyperscan.SomLeftMost|hyperscan.Utf8Mode)
	pattern3.Id = 3
	pattern4 := hyperscan.NewPattern(rm["ADDRESS"].(map[string]interface{})["rule"].(string), hyperscan.SomLeftMost|hyperscan.Utf8Mode)
	pattern4.Id = 4
	patterns = append(patterns, pattern1, pattern2, pattern3, pattern4)
	gohs := &gohs2.Gohs{
		Patterns: patterns,
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
