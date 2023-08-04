package match

import (
	"github.com/yasin-wu/dsi_engine/v2/pkg/entity"
	pkgregexp "github.com/yasin-wu/dsi_engine/v2/pkg/regexp"
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
	if rule.Regexp == "" {
		return nil, false
	}
	engine, err := pkgregexp.New(&entity.Regexp{Regexp: rule.Regexp})
	if err != nil {
		return nil, false
	}
	matches, err := engine.Run(inputData)
	if err != nil {
		return nil, false
	}
	if len(matches) < rule.ForwardThreshold {
		return nil, false
	}
	return matches, true
}
