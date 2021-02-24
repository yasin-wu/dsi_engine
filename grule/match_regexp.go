package grule

import (
	gohs2 "github.com/yasin-wu/dlp/gohs"
	"github.com/yasin-wu/dlp/policy"
)

/**
* @author: yasin
* @date: 2020/6/24 15:53
* @description：RuleTypeRegexpTag
 */
func (this *GRule) matchRegexp(ruleContent *policy.RuleContent) ([]*gohs2.Match, string, bool) {
	inputData := this.filePolicy.FileName
	matches, matched := this.doMatchRegexp(ruleContent, this.filePolicy.FileName)
	if !matched {
		inputData = this.filePolicy.Content
		matches, matched = this.doMatchRegexp(ruleContent, this.filePolicy.Content)
	}
	return matches, inputData, matched
}

func (this *GRule) doMatchRegexp(ruleContent *policy.RuleContent, inputData string) ([]*gohs2.Match, bool) {
	regexp := ruleContent.Regexp
	if regexp == "" {
		return nil, false
	}
	gohs := gohs2.New(&gohs2.Regexp{Regexp: regexp})
	matches, err := gohs.Run(inputData)
	if err != nil {
		return nil, false
	}
	if len(matches) < ruleContent.ForWardThreshold {
		return nil, false
	}
	return matches, true
}
