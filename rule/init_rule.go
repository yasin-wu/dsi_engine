package rule

import (
	"fmt"
	js "github.com/bitly/go-simplejson"
	"io/ioutil"
	"os"
)

var RulesMap = make(map[string]interface{})

func InitRule() error {
	pwd, _ := os.Getwd()
	filePath := fmt.Sprintf("%s/%s", pwd, "rule/rules.json")
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
	RulesMap, err = j.Map()
	if err != nil {
		return err
	}
	return nil
}
