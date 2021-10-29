package dsi_engine

import (
	"github.com/yasin-wu/dsi_engine/policy"
	"github.com/yasin-wu/dsi_engine/regexp_engine"
)

type KeyWords struct {
	dsiEngine *DsiEngine
}

var _ MatchEngine = (*KeyWords)(nil)

func (this *KeyWords) match(rule *policy.Rule) ([]*regexp_engine.Match, string, bool) {
	inputData := this.dsiEngine.sensitiveData.FileName
	matches, matched := this.do(rule, this.dsiEngine.sensitiveData.FileName)
	if !matched {
		inputData = this.dsiEngine.sensitiveData.Content
		matches, matched = this.do(rule, this.dsiEngine.sensitiveData.Content)
	}
	return matches, inputData, matched
}

func (this *KeyWords) do(rule *policy.Rule, inputData string) ([]*regexp_engine.Match, bool) {
	exitReverse := len(rule.ReverseKeyList) > 0
	if exitReverse {
		regexps := this.regexps(rule.ReverseKeyList)
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
	regexps := this.regexps(rule.ForWardKeyList)
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

func (this *KeyWords) regexps(keyWords []string) []*regexp_engine.Regexp {
	var regexps []*regexp_engine.Regexp
	for _, word := range keyWords {
		regexp := &regexp_engine.Regexp{
			Regexp: word,
		}
		regexps = append(regexps, regexp)
	}
	return regexps
}
