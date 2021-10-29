package dsi_engine

import (
	"github.com/yasin-wu/dsi_engine/policy"
	"github.com/yasin-wu/dsi_engine/regexp_engine"
)

type Regexp struct {
	dsiEngine *DsiEngine
}

var _ MatchEngine = (*Regexp)(nil)

func (this *Regexp) match(rule *policy.Rule) ([]*regexp_engine.Match, string, bool) {
	inputData := this.dsiEngine.sensitiveData.FileName
	matches, matched := this.regexp(rule, this.dsiEngine.sensitiveData.FileName)
	if !matched {
		inputData = this.dsiEngine.sensitiveData.Content
		matches, matched = this.regexp(rule, this.dsiEngine.sensitiveData.Content)
	}
	return matches, inputData, matched
}

func (this *Regexp) regexp(rule *policy.Rule, inputData string) ([]*regexp_engine.Match, bool) {
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
