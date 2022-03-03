package dsi_engine

import (
	"github.com/yasin-wu/dsi_engine/v2/policy"
	"github.com/yasin-wu/dsi_engine/v2/regexp_engine"
)

type keyWords struct {
	dsiEngine *DsiEngine
}

var _ MatchEngine = (*keyWords)(nil)

func (k *keyWords) match(rule *policy.Rule) ([]*regexp_engine.Match, string, bool) {
	inputData := k.dsiEngine.sensitiveData.FileName
	matches, matched := k.do(rule, k.dsiEngine.sensitiveData.FileName)
	if !matched {
		inputData = k.dsiEngine.sensitiveData.Content
		matches, matched = k.do(rule, k.dsiEngine.sensitiveData.Content)
	}
	return matches, inputData, matched
}

func (k *keyWords) do(rule *policy.Rule, inputData string) ([]*regexp_engine.Match, bool) {
	exitReverse := len(rule.ReverseKeyList) > 0
	if exitReverse {
		regexps := k.regexps(rule.ReverseKeyList)
		if regexps == nil {
			return nil, false
		}
		engine, err := regexp_engine.New(regexps...)
		if err != nil {
			return nil, false
		}
		matches, err := engine.Run(inputData)
		if err != nil {
			return nil, false
		}
		if len(matches) >= rule.ReverseThreshold {
			return nil, false
		}
	}
	regexps := k.regexps(rule.ForWardKeyList)
	if regexps == nil {
		return nil, false
	}
	engine, err := regexp_engine.New(regexps...)
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

func (k *keyWords) regexps(keyWords []string) []*regexp_engine.Regexp {
	var regexps []*regexp_engine.Regexp
	for _, word := range keyWords {
		regexp := &regexp_engine.Regexp{
			Regexp: word,
		}
		regexps = append(regexps, regexp)
	}
	return regexps
}
