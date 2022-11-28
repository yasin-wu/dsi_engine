[![OSCS Status](https://www.oscs1024.com/platform/badge/yasin-wu/dsi_engine.svg?size=small)](https://www.murphysec.com/dr/Qy5A7cERejgZNnm0Nw)
## 介绍

Golang版本的自定义规则的敏感信息识别引擎(Detection Sensitive Information Engine)，使用了Intel的高性能正则表达式匹配库Hyperscan；只适用X86架构。

## 安装

可使用Dockerfile安装Hyperscan环境

```
os:
    - linux
    - osx
addons:
    apt:
        packages:
            - libhyperscan-dev
            - libpcap-dev
            - tree
            - gcc
            - clang
            - ca-certificates 
            - openssl
            - g++
    homebrew:
        packages:
            - pkg-config
            - hyperscan
            - libpcap
            - tree
package:
go get -u github.com/flier/gohs
go get -u github.com/hyperjumptech/grule-rule-engine
go get -u github.com/yasin-wu/dsi_engine
```

推荐使用go.mod

```
require github.com/yasin-wu/dsi_engine/v2 v2.3.1
```

## 使用DsiEngine

```go
func TestDsiEngine(t *testing.T) {
	rule, err := rule2.New()
	if err != nil {
		log.Fatal(err)
	}
	rulesMap := rule.RuleMap
	sensitiveData := &entity.SensitiveData{
		FilePath: "../sample/test.docx",
	}
	parser(sensitiveData)
	sensitiveData.Policies = handlePolicies(rulesMap)
	engine := engine.New()
	alarms, err := engine.Run(sensitiveData)
	if err != nil {
		log.Fatal(err)
	}
	buff, _ := json.MarshalIndent(alarms, "", "\t")
	fmt.Println(string(buff))
}

func parser(sensitiveData *entity.SensitiveData) {
	parser := file_parser.New("http://47.108.155.25:9998")
	f, err := parser.Parse(sensitiveData.FilePath, true)
	if err != nil {
		log.Fatal(err)
	}
	sensitiveData.FileName = f.Name
	sensitiveData.FileType = f.FileType
	sensitiveData.FileSize = f.Size
	sensitiveData.Content = f.Content
}

func handlePolicies(rulesMap map[string]rule2.R) []*entity.Policy {
	rule1 := entity.Rule{
		Id:               "1",
		Name:             "正则匹配:地址信息",
		Type:             enum.REGEXP_RULETYPE,
		Regexp:           rulesMap["ADDRESS"].Regexp,
		ForWardThreshold: 1,
	}
	rule2 := entity.Rule{
		Id:               "2",
		Name:             "模糊关键字:我们",
		Type:             enum.FUZZYWORDS_RULETYPE,
		ForWardKeyList:   []string{"我们"},
		CharacterSpace:   5,
		ForWardThreshold: 1,
	}
	policy1 := &entity.Policy{
		Id:        "1",
		Operators: []enum.Operator{enum.AND_OPERATOR},
		Rules:     []entity.Rule{rule1, rule2},
	}
	policy2 := &entity.Policy{
		Id:        "2",
		Operators: []enum.Operator{enum.OR_OPERATOR},
		Rules:     []entity.Rule{rule1, rule2},
	}
	var policies []*entity.Policy
	policies = append(policies, policy1, policy2)
	return policies
}

```

## 使用RegexpEngine

```go
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
	err = rule.Add("../conf/rules.json", m)
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

```
