package dsi_engine

import (
	"fmt"
	"strings"

	"github.com/yasin-wu/dsi_engine/v2/policy"
	"github.com/yasin-wu/dsi_engine/v2/regexp_engine"
)

type fuzzyWords struct {
	dsiEngine *DsiEngine
}

var _ MatchEngine = (*fuzzyWords)(nil)

func (f *fuzzyWords) match(rule *policy.Rule) ([]*regexp_engine.Match, string, bool) {
	inputData := f.dsiEngine.sensitiveData.FileName
	matches, matched := f.do(rule, f.dsiEngine.sensitiveData.FileName)
	if !matched {
		inputData = f.dsiEngine.sensitiveData.Content
		matches, matched = f.do(rule, f.dsiEngine.sensitiveData.Content)
	}
	return matches, inputData, matched
}

func (f *fuzzyWords) do(rule *policy.Rule, inputData string) ([]*regexp_engine.Match, bool) {
	baseRegexp := rule.ForWardKeyList
	characterSpace := rule.CharacterSpace
	regexps := f.regexps(baseRegexp, fmt.Sprintf("%d", characterSpace))
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

func (f *fuzzyWords) regexps(baseRegexp []string, characterSpace string) []*regexp_engine.Regexp {
	characterSpace = fmt.Sprintf(`.{0,%s}`, characterSpace)
	var regexps []*regexp_engine.Regexp
	for _, b := range baseRegexp {
		wordList := strings.Split(b, "")
		word := ""
		for _, w := range wordList {
			word += w + characterSpace
		}
		word = word[0:strings.LastIndex(word, characterSpace)]
		regexp := &regexp_engine.Regexp{
			Regexp: word,
		}
		regexps = append(regexps, regexp)
	}
	return regexps
}
