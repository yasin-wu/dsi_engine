package grule

import (
	gohs2 "github.com/yasin-wu/dlp/gohs"
	"github.com/yasin-wu/dlp/policy"
)

/**
 * @author: yasin
 * @date: 2020/6/24 15:53
 * @description：RuleTypeKeyWords
 */
func (this *GRule) matchKeyWords(ruleContent *policy.RuleContent) ([]*gohs2.Match, string, bool) {
	inputData := this.filePolicy.FileName
	matches, matched := this.doMatchKeyWords(ruleContent, this.filePolicy.FileName)
	if !matched {
		inputData = this.filePolicy.Content
		matches, matched = this.doMatchKeyWords(ruleContent, this.filePolicy.Content)
	}
	return matches, inputData, matched
}

func (this *GRule) doMatchKeyWords(ruleContent *policy.RuleContent, inputData string) ([]*gohs2.Match, bool) {
	exitReverse := len(ruleContent.ReverseKeyList) > 0
	if exitReverse {
		regexps := this.getKeyWordsRegexps(ruleContent.ReverseKeyList)
		if regexps == nil {
			return nil, false
		}
		gohs, err := gohs2.New(regexps...)
		if err != nil {
			return nil, false
		}
		matches, err := gohs.Run(inputData)
		if err != nil {
			return nil, false
		}
		if len(matches) >= ruleContent.ReverseThreshold {
			return nil, false
		}
	}
	regexps := this.getKeyWordsRegexps(ruleContent.ForWardKeyList)
	if regexps == nil {
		return nil, false
	}
	gohs, err := gohs2.New(regexps...)
	if err != nil {
		return nil, false
	}
	matches, err := gohs.Run(inputData)
	if err != nil {
		return nil, false
	}
	if len(matches) < ruleContent.ForWardThreshold {
		return nil, false
	}
	return matches, true
}

func (this *GRule) getKeyWordsRegexps(keyWords []string) []*gohs2.Regexp {
	var regexps []*gohs2.Regexp
	for _, word := range keyWords {
		regexp := &gohs2.Regexp{
			Regexp: word,
		}
		regexps = append(regexps, regexp)
	}
	return regexps
}
