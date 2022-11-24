package rule

import (
	"encoding/json"
	"io/ioutil"
	"os"

	"github.com/yasin-wu/dsi_engine/v2/pkg/consts"
)

/**
 * @author: yasinWu
 * @date: 2022/1/13 13:51
 * @description: Rule
 */
type Rule struct {
	RuleMap map[string]R
}

/**
 * @author: yasinWu
 * @date: 2022/1/13 13:51
 * @description: R
 */
type R struct {
	Regexp string `json:"regexp"`
	Desc   string `json:"desc"`
}

/**
 * @author: yasinWu
 * @date: 2022/1/13 13:51
 * @return: *Rule, error
 * @description: 获取系统内置规则
 */
func New() (*Rule, error) {
	ruleBytes := []byte(defaultRule)
	ruleMap := make(map[string]interface{})
	rm := make(map[string]R)
	if err := json.Unmarshal(ruleBytes, &ruleMap); err != nil {
		return nil, err
	}
	for k, v := range ruleMap {
		var r R
		if err := unmarshal(v, &r); err != nil {
			continue
		}
		rm[k] = r
	}
	return &Rule{
		RuleMap: rm,
	}, nil
}

/**
 * @author: yasinWu
 * @date: 2022/1/13 13:52
 * @params: filePath string, ruleMap ...map[string]R
 * @return: error
 * @description: 添加自定义规则集
 */
func (r *Rule) Add(filePath string, ruleMap ...map[string]R) error {
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
	contentMap := make(map[string]interface{})
	if err := json.Unmarshal(content, &contentMap); err != nil {
		return err
	}
	for k, v := range contentMap {
		var rr R
		if err = unmarshal(v, &rr); err != nil {
			continue
		}
		r.RuleMap[k] = rr
	}
	for _, v := range ruleMap {
		for k, v1 := range v {
			r.RuleMap[k] = v1
		}
	}
	return nil
}

func unmarshal(data any, v *R) error {
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
