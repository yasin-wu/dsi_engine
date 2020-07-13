package models

import (
	"github.com/flier/gohs/hyperscan"
	"testing"
)

func TestGohs_Run(t *testing.T) {
	inputData := "测试IPV6地址正则:fe80::ec61:c1d1:9827:82be%13"
	var patterns []*hyperscan.Pattern
	pattern := hyperscan.NewPattern(IPV6Reg, hyperscan.SomLeftMost|hyperscan.Utf8Mode)
	pattern.Id = 1
	patterns = append(patterns, pattern)
	gohs := &Gohs{
		Patterns: patterns,
	}
	matches, err := gohs.Run(inputData)
	if err != nil {
		t.Error(err.Error())
		return
	}
	for _, m := range matches {
		t.Log("id:", m.Id, m.InputData[m.From:m.To])
	}
}
