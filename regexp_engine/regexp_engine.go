package regexp_engine

import (
	"errors"
	"fmt"

	"github.com/flier/gohs/hyperscan"
)

/**
 * @author: yasin
 * @date: 2022/1/13 13:48
 * @description: 命中信息
 */
type Match struct {
	Id        uint        //命中信息id
	From      uint64      //命中开始位置
	To        uint64      //名字结束位置
	Flags     uint        //flags
	Context   interface{} //命中内容
	InputData string      //输入内容
	Distance  int         //汉明距离
}

/**
 * @author: yasin
 * @date: 2022/1/13 13:49
 * @description: 正则信息
 */
type Regexp struct {
	Id     int    //正则id
	Regexp string //正则表达式
}

/**
 * @author: yasin
 * @date: 2022/1/13 13:49
 * @description: RegexpEngine Client
 */
type RegexpEngine struct {
	patterns []*hyperscan.Pattern
}

/**
 * @author: yasin
 * @date: 2022/1/13 13:50
 * @params: regexps ...*Regexp
 * @return: *RegexpEngine, error
 * @description: 新建RegexpEngine Client
 */
func New(regexps ...*Regexp) (*RegexpEngine, error) {
	patterns := addRegexps(regexps...)
	if patterns == nil || len(patterns) == 0 {
		return nil, errors.New("parameter is empty")
	}
	return &RegexpEngine{patterns: patterns}, nil
}

/**
 * @author: yasin
 * @date: 2022/1/13 13:50
 * @params: inputData string
 * @return: []*Match, error
 * @description: 检测输入内容敏感信息
 */
func (r *RegexpEngine) Run(inputData string) ([]*Match, error) {
	db, err := hyperscan.NewBlockDatabase(r.patterns...)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("NewBlockDatabase err: %v", err.Error()))
	}
	defer db.Close()
	s, err := hyperscan.NewScratch(db)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("create scratch failed, err: %v", err.Error()))
	}
	defer s.Free()
	var matches []*Match
	matched := func(id uint, from, to uint64, flags uint, context interface{}) error {
		match := &Match{Id: id, From: from, To: to, Flags: flags, Context: context, InputData: inputData}
		matches = append(matches, match)
		return nil
	}

	if err := db.Scan([]byte(inputData), s, matched, nil); err != nil {
		return nil, errors.New(fmt.Sprintf("database scan failed, err: %v", err.Error()))
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
