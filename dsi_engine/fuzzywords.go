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

var _ matchEngine = (*fuzzyWords)(nil)

func (this *fuzzyWords) match(rule *policy.Rule) ([]*regexp_engine.Match, string, bool) {
	inputData := this.dsiEngine.sensitiveData.FileName
	matches, matched := this.do(rule, this.dsiEngine.sensitiveData.FileName)
	if !matched {
		inputData = this.dsiEngine.sensitiveData.Content
		matches, matched = this.do(rule, this.dsiEngine.sensitiveData.Content)
	}
	return matches, inputData, matched
}

func (this *fuzzyWords) do(rule *policy.Rule, inputData string) ([]*regexp_engine.Match, bool) {
	baseRegexp := rule.ForWardKeyList
	characterSpace := rule.CharacterSpace
	regexps := this.regexps(baseRegexp, fmt.Sprintf("%d", characterSpace))
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

func (this *fuzzyWords) regexps(baseRegexp []string, characterSpace string) []*regexp_engine.Regexp {
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
