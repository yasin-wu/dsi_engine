package dlp

import (
	"github.com/flier/gohs/hyperscan"
)

/**
* @author: yasin
* @date: 2020/6/24 15:53
* @description：RuleTypeRegexpTag
 */
func (this *GRule) MatchRegexp(ruleContent *RuleContent) ([]*Match, string, bool) {
	inputData := this.FilePolicy.FileName
	matches, matched := this.matchRegexp(ruleContent, this.FilePolicy.FileName)
	if !matched {
		inputData = this.FilePolicy.Content
		matches, matched = this.matchRegexp(ruleContent, this.FilePolicy.Content)
	}
	return matches, inputData, matched
}

func (this *GRule) matchRegexp(ruleContent *RuleContent, inputData string) ([]*Match, bool) {
	regexp := ruleContent.Regexp
	patterns := this.getRegexpPatterns(regexp)
	if patterns == nil {
		return nil, false
	}
	gohs := &Gohs{Patterns: patterns}
	matches, err := gohs.Run(inputData)
	if err != nil {
		return nil, false
	}
	if len(matches) < ruleContent.ForWardThreshold {
		return nil, false
	}
	return matches, true
}

func (this *GRule) getRegexpPatterns(regexp string) []*hyperscan.Pattern {
	var patterns []*hyperscan.Pattern
	pattern := hyperscan.NewPattern(regexp, hyperscan.SomLeftMost|hyperscan.Utf8Mode)
	patterns = append(patterns, pattern)
	return patterns
}
