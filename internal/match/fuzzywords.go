package match

import (
	"fmt"
	"strings"

	regexp2 "github.com/yasin-wu/dsi_engine/v2/pkg/regexp"

	"github.com/yasin-wu/dsi_engine/v2/pkg/entity"
)

type fuzzyWords struct{}

var _ Engine = (*fuzzyWords)(nil)

func (f *fuzzyWords) Match(rule entity.Rule, sensitiveData entity.SensitiveData) ([]*entity.Match, string, bool) {
	inputData := sensitiveData.FileName
	matches, matched := f.do(rule, sensitiveData.FileName)
	if !matched {
		inputData = sensitiveData.Content
		matches, matched = f.do(rule, sensitiveData.Content)
	}
	return matches, inputData, matched
}

func (f *fuzzyWords) do(rule entity.Rule, inputData string) ([]*entity.Match, bool) {
	baseRegexp := rule.ForWardKeyList
	characterSpace := rule.CharacterSpace
	regexps := f.regexps(baseRegexp, fmt.Sprintf("%d", characterSpace))
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

func (f *fuzzyWords) regexps(baseRegexp []string, characterSpace string) []*regexp2.Regexp {
	characterSpace = fmt.Sprintf(`.{0,%s}`, characterSpace)
	var regexps []*regexp2.Regexp
	for _, b := range baseRegexp {
		wordList := strings.Split(b, "")
		word := ""
		for _, w := range wordList {
			word += w + characterSpace
		}
		word = word[0:strings.LastIndex(word, characterSpace)]
		regexp := &regexp2.Regexp{
			Regexp: word,
		}
		regexps = append(regexps, regexp)
	}
	return regexps
}
