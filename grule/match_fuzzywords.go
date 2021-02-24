package grule

import (
	"fmt"
	gohs2 "github.com/yasin-wu/dlp/gohs"
	"github.com/yasin-wu/dlp/policy"
	"strings"
)

/**
 * @author: yasin
 * @date: 2020/6/24 15:53
 * @description：RuleTypeFuzzyWords
 */
func (this *GRule) matchFuzzyWords(ruleContent *policy.RuleContent) ([]*gohs2.Match, string, bool) {
	inputData := this.filePolicy.FileName
	matches, matched := this.doMatchFuzzyWords(ruleContent, this.filePolicy.FileName)
	if !matched {
		inputData = this.filePolicy.Content
		matches, matched = this.doMatchFuzzyWords(ruleContent, this.filePolicy.Content)
	}
	return matches, inputData, matched
}

func (this *GRule) doMatchFuzzyWords(ruleContent *policy.RuleContent, inputData string) ([]*gohs2.Match, bool) {
	baseRegexp := ruleContent.ForWardKeyList
	characterSpace := ruleContent.CharacterSpace
	regexps := this.getFuzzyWordsRegexps(baseRegexp, fmt.Sprintf("%d", characterSpace))
	if regexps == nil {
		return nil, false
	}
	gohs := gohs2.New(regexps...)
	matches, err := gohs.Run(inputData)
	if err != nil {
		return nil, false
	}
	if len(matches) < ruleContent.ForWardThreshold {
		return nil, false
	}
	return matches, true
}

func (this *GRule) getFuzzyWordsRegexps(baseRegexp []string, characterSpace string) []*gohs2.Regexp {
	characterSpace = fmt.Sprintf(`.{0,%s}`, characterSpace)
	var regexps []*gohs2.Regexp
	for _, b := range baseRegexp {
		wordList := strings.Split(b, "")
		word := ""
		for _, w := range wordList {
			word += w + characterSpace
		}
		word = word[0:strings.LastIndex(word, characterSpace)]
		regexp := &gohs2.Regexp{
			Regexp: word,
		}
		regexps = append(regexps, regexp)
	}
	return regexps
}
