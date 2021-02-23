package rule

import (
	js "github.com/bitly/go-simplejson"
	"github.com/yasin-wu/dlp/consts"
	"io/ioutil"
	"os"
)

var RulesMap = make(map[string]interface{})

func InitRule() error {
	ruleBytes := []byte(rule)
	j, err := js.NewJson(ruleBytes)
	if err != nil {
		return err
	}
	RulesMap, err = j.Map()
	if err != nil {
		return err
	}
	return nil
}

func AddRule(filePath string) error {
	if filePath == "" {
		return consts.ErrParameterEmpty
	}
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()
	content, err := ioutil.ReadAll(file)
	if err != nil {
		return err
	}
	j, err := js.NewJson(content)
	if err != nil {
		return err
	}
	m, err := j.Map()
	if err != nil {
		return err
	}
	for k, v := range m {
		RulesMap[k] = v
	}
	return nil
}
