package match

import (
	"github.com/yasin-wu/dsi_engine/v2/entity"
	regexp2 "github.com/yasin-wu/dsi_engine/v2/regexp"
)

type keyWords struct{}

var _ Engine = (*keyWords)(nil)

func (k *keyWords) Match(rule entity.Rule, sensitiveData entity.SensitiveData) ([]*entity.Match, string, bool) {
	inputData := sensitiveData.FileName
	matches, matched := k.do(rule, sensitiveData.FileName)
	if !matched {
		inputData = sensitiveData.Content
		matches, matched = k.do(rule, sensitiveData.Content)
	}
	return matches, inputData, matched
}

func (k *keyWords) do(rule entity.Rule, inputData string) ([]*entity.Match, bool) {
	exitReverse := len(rule.ReverseKeyList) > 0
	if exitReverse {
		regexps := k.regexps(rule.ReverseKeyList)
		if regexps == nil {
			return nil, false
		}
		engine, err := regexp2.New(regexps...)
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
	engine, err := regexp2.New(regexps...)
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

func (k *keyWords) regexps(keyWords []string) []*regexp2.Regexp {
	var regexps []*regexp2.Regexp
	for _, word := range keyWords {
		regexp := &regexp2.Regexp{
			Regexp: word,
		}
		regexps = append(regexps, regexp)
	}
	return regexps
}
