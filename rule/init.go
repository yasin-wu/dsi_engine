package rule

import (
	"encoding/json"
	"io/ioutil"
	"os"

	js "github.com/bitly/go-simplejson"
	"github.com/yasin-wu/dsi_engine/v2/consts"
)

type Rule struct {
	RuleMap map[string]R
}

type R struct {
	Regexp string `json:"regexp"`
	Desc   string `json:"desc"`
}

func New() (*Rule, error) {
	ruleBytes := []byte(defaultRule)
	j, err := js.NewJson(ruleBytes)
	if err != nil {
		return nil, err
	}
	ruleMap, err := j.Map()
	if err != nil {
		return nil, err
	}
	var rm = make(map[string]R)
	for k, v := range ruleMap {
		var r R
		err = unmarshal(v, &r)
		if err != nil {
			continue
		}
		rm[k] = r
	}
	return &Rule{
		RuleMap: rm,
	}, nil
}

func (this *Rule) Add(filePath string, ruleMap ...map[string]R) error {
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
		var r R
		err = unmarshal(v, &r)
		if err != nil {
			continue
		}
		this.RuleMap[k] = r
	}
	for _, v := range ruleMap {
		for k, v1 := range v {
			this.RuleMap[k] = v1
		}
	}
	return nil
}

func unmarshal(data interface{}, v *R) error {
	buff, err := json.Marshal(data)
	if err != nil {
		return err
	}
	err = json.Unmarshal(buff, &v)
	if err != nil {
		return err
	}
	return nil
}
