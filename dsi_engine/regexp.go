package dsi_engine

import (
	"github.com/yasin-wu/dsi_engine/v2/policy"
	"github.com/yasin-wu/dsi_engine/v2/regexp_engine"
)

type regexp struct {
	dsiEngine *DsiEngine
}

var _ MatchEngine = (*regexp)(nil)

func (r *regexp) match(rule *policy.Rule) ([]*regexp_engine.Match, string, bool) {
	inputData := r.dsiEngine.sensitiveData.FileName
	matches, matched := r.regexp(rule, r.dsiEngine.sensitiveData.FileName)
	if !matched {
		inputData = r.dsiEngine.sensitiveData.Content
		matches, matched = r.regexp(rule, r.dsiEngine.sensitiveData.Content)
	}
	return matches, inputData, matched
}

func (r *regexp) regexp(rule *policy.Rule, inputData string) ([]*regexp_engine.Match, bool) {
	regexp := rule.Regexp
	if regexp == "" {
		return nil, false
	}
	engine, err := regexp_engine.New(&regexp_engine.Regexp{Regexp: regexp})
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
