package match

import (
	"github.com/yasin-wu/dsi_engine/v2/entity"
	regexp2 "github.com/yasin-wu/dsi_engine/v2/regexp"
)

type regexp struct{}

var _ Engine = (*regexp)(nil)

func (r *regexp) Match(rule entity.Rule, sensitiveData entity.SensitiveData) ([]*entity.Match, string, bool) {
	inputData := sensitiveData.FileName
	matches, matched := r.regexp(rule, sensitiveData.FileName)
	if !matched {
		inputData = sensitiveData.Content
		matches, matched = r.regexp(rule, sensitiveData.Content)
	}
	return matches, inputData, matched
}

func (r *regexp) regexp(rule entity.Rule, inputData string) ([]*entity.Match, bool) {
	regexp := rule.Regexp
	if regexp == "" {
		return nil, false
	}
	engine, err := regexp2.New(&regexp2.Regexp{Regexp: regexp})
	if err != nil {
		return nil, false
	}
	matches, err := engine.Run(inputData)
	if err != nil {
		return nil, false
	}
	if len(matches) < rule.ForWardThreshold {
		return nil, false
	}
	return matches, true
}
