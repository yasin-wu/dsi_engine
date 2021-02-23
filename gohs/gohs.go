package gohs

import (
	"errors"
	"fmt"
	"github.com/flier/gohs/hyperscan"
	"github.com/yasin-wu/dlp/rule"
)

type Match struct {
	Id        uint
	From      uint64
	To        uint64
	Flags     uint
	Context   interface{}
	InputData string
}

type Gohs struct {
	Patterns []*hyperscan.Pattern
}

func (this *Gohs) Run(inputData string) ([]*Match, error) {
	if rule.RulesMap == nil || len(rule.RulesMap) == 0 {
		return nil, errors.New("RulesMap is nil")
	}
	db, err := hyperscan.NewBlockDatabase(this.Patterns...)
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
