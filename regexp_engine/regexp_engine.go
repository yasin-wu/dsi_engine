package regexp_engine

import (
	"errors"
	"fmt"

	"github.com/flier/gohs/hyperscan"
)

type Match struct {
	Id        uint
	From      uint64
	To        uint64
	Flags     uint
	Context   interface{}
	InputData string
	Distance  int
}

type Regexp struct {
	Id     int
	Regexp string
}

type RegexpEngine struct {
	patterns []*hyperscan.Pattern
}

func New(regexps ...*Regexp) (*RegexpEngine, error) {
	if regexps == nil || len(regexps) == 0 {
		return nil, errors.New("parameter is empty")
	}
	return &RegexpEngine{patterns: addRegexps(regexps...)}, nil
}

func (this *RegexpEngine) Run(inputData string) ([]*Match, error) {
	db, err := hyperscan.NewBlockDatabase(this.patterns...)
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
