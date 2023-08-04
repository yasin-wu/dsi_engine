package regexp

import (
	"errors"
	"github.com/yasin-wu/dsi_engine/v2/pkg/entity"
	"regexp"
)

/**
 * @author: yasinWu
 * @date: 2022/1/13 13:49
 * @description: Engine Client
 */
type Engine struct {
	regexps []*entity.Regexp
}

/**
 * @author: yasinWu
 * @date: 2022/1/13 13:50
 * @params: regexps ...*Regexp
 * @return: *Engine, error
 * @description: 新建RegexpEngine Client
 */
func New(regexps ...*entity.Regexp) (*Engine, error) {
	if len(regexps) == 0 {
		return nil, errors.New("regexps is empty")
	}
	return &Engine{regexps: regexps}, nil
}

/**
 * @author: yasinWu
 * @date: 2022/1/13 13:50
 * @params: inputData string
 * @return: []*Match, error
 * @description: 检测输入内容敏感信息
 */
func (r *Engine) Run(inputData string) ([]*entity.Match, error) {
	var matches []*entity.Match
	for _, v := range r.regexps {
		reg := regexp.MustCompile(v.Regexp)
		loc := reg.FindStringIndex(inputData)
		if len(loc) == 2 {
			matches = append(matches, &entity.Match{
				ID:        v.ID,
				From:      loc[0],
				To:        loc[1],
				Context:   inputData[loc[0]:loc[1]],
				InputData: inputData,
				Distance:  0,
			})
		}
	}
	return matches, nil
}
