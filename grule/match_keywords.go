package grule

import (
	"github.com/flier/gohs/hyperscan"
	"github.com/yasin-wu/dlp/gohs"
	"github.com/yasin-wu/dlp/policy"
)

/**
 * @author: yasin
 * @date: 2020/6/24 15:53
 * @description：RuleTypeKeyWords
 */
func (this *GRule) MatchKeyWords(ruleContent *policy.RuleContent) ([]*gohs.Match, string, bool) {
	inputData := this.FilePolicy.FileName
	matches, matched := this.matchKeyWords(ruleContent, this.FilePolicy.FileName)
	if !matched {
		inputData = this.FilePolicy.Content
		matches, matched = this.matchKeyWords(ruleContent, this.FilePolicy.Content)
	}
	return matches, inputData, matched
}

func (this *GRule) matchKeyWords(ruleContent *policy.RuleContent, inputData string) ([]*gohs.Match, bool) {
	exitReverse := len(ruleContent.ReverseKeyList) > 0
	if exitReverse {
		patterns := this.getKeyWordsPatterns(ruleContent.ReverseKeyList)
		if patterns == nil {
			return nil, false
		}
		gohs := &gohs.Gohs{Patterns: patterns}
		matches, err := gohs.Run(inputData)
		if err != nil {
			return nil, false
		}
		if len(matches) >= ruleContent.ReverseThreshold {
			return nil, false
		}
	}
	patterns := this.getKeyWordsPatterns(ruleContent.ForWardKeyList)
	if patterns == nil {
		return nil, false
	}
	gohs := &gohs.Gohs{Patterns: patterns}
	matches, err := gohs.Run(inputData)
	if err != nil {
		return nil, false
	}
	if len(matches) < ruleContent.ForWardThreshold {
		return nil, false
	}
	return matches, true
}

func (this *GRule) getKeyWordsPatterns(keyWords []string) []*hyperscan.Pattern {
	var patterns []*hyperscan.Pattern
	for _, word := range keyWords {
		pattern := hyperscan.NewPattern(word, hyperscan.SomLeftMost|hyperscan.Utf8Mode)
		patterns = append(patterns, pattern)
	}
	return patterns
}