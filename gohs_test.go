package dlp

import (
	"testing"

	"github.com/flier/gohs/hyperscan"
)

func TestGohs(t *testing.T) {
	inputData := "My name is Bob;电话号码:18108279331;测试IPV6地址正则:fe80::ec61:c1d1:9827:82be%13"
	var patterns []*hyperscan.Pattern
	pattern1 := hyperscan.NewPattern(IPV6Reg, hyperscan.SomLeftMost|hyperscan.Utf8Mode)
	pattern1.Id = 1
	pattern2 := hyperscan.NewPattern("Bob", hyperscan.SomLeftMost|hyperscan.Utf8Mode)
	pattern2.Id = 2
	pattern3 := hyperscan.NewPattern(TelNumReg, hyperscan.SomLeftMost|hyperscan.Utf8Mode)
	pattern3.Id = 3
	patterns = append(patterns, pattern1, pattern2, pattern3)
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
