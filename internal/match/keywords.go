package match

import (
	"github.com/yasin-wu/dsi_engine/v2/pkg/entity"
	pkgregexp "github.com/yasin-wu/dsi_engine/v2/pkg/regexp"
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
		engine, err := pkgregexp.New(regexps...)
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
	regexps := k.regexps(rule.ForwardKeyList)
	if regexps == nil {
		return nil, false
	}
	engine, err := pkgregexp.New(regexps...)
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

func (k *keyWords) regexps(keyWords []string) []*entity.Regexp {
	var regexps []*entity.Regexp
	for _, word := range keyWords {
		regexps = append(regexps, &entity.Regexp{
			Regexp: word,
		})
	}
	return regexps
}
