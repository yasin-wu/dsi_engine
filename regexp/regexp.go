package regexp

import (
	"errors"
	"fmt"

	"github.com/yasin-wu/dsi_engine/v2/entity"

	"github.com/flier/gohs/hyperscan"
)

/**
 * @author: yasinWu
 * @date: 2022/1/13 13:49
 * @description: 正则信息
 */
type Regexp struct {
	Id     int    // 正则id
	Regexp string // 正则表达式
}

/**
 * @author: yasinWu
 * @date: 2022/1/13 13:49
 * @description: Engine Client
 */
type Engine struct {
	patterns []*hyperscan.Pattern
}

/**
 * @author: yasinWu
 * @date: 2022/1/13 13:50
 * @params: regexps ...*Regexp
 * @return: *Engine, error
 * @description: 新建RegexpEngine Client
 */
func New(regexps ...*Regexp) (*Engine, error) {
	patterns := addRegexps(regexps...)
	if patterns == nil || len(patterns) == 0 {
		return nil, errors.New("parameter is empty")
	}
	return &Engine{patterns: patterns}, nil
}

/**
 * @author: yasinWu
 * @date: 2022/1/13 13:50
 * @params: inputData string
 * @return: []*Match, error
 * @description: 检测输入内容敏感信息
 */
func (r *Engine) Run(inputData string) ([]*entity.Match, error) {
	db, err := hyperscan.NewBlockDatabase(r.patterns...)
	if err != nil {
		return nil, fmt.Errorf("NewBlockDatabase err: %v", err.Error())
	}
	defer db.Close()
	s, err := hyperscan.NewScratch(db)
	if err != nil {
		return nil, fmt.Errorf("create scratch failed, err: %v", err.Error())
	}
	defer s.Free()
	var matches []*entity.Match
	matched := func(id uint, from, to uint64, flags uint, context any) error {
		match := &entity.Match{ID: id, From: from, To: to, Flags: flags, Context: context, InputData: inputData}
		matches = append(matches, match)
		return nil
	}

	if err := db.Scan([]byte(inputData), s, matched, nil); err != nil {
		return nil, fmt.Errorf("database scan failed, err: %v", err.Error())
	}
	return matches, nil
}

func addRegexps(regexps ...*Regexp) []*hyperscan.Pattern {
	var patterns []*hyperscan.Pattern
	for _, v := range regexps {
		if v.Regexp == "" {
			continue
		}
		pattern := hyperscan.NewPattern(v.Regexp, hyperscan.SomLeftMost|hyperscan.Utf8Mode)
		pattern.Id = v.Id
		patterns = append(patterns, pattern)
	}
	return patterns
}
