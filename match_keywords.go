package dlp

import (
	"github.com/flier/gohs/hyperscan"
)

/**
 * @author: yasin
 * @date: 2020/6/24 15:53
 * @description：RuleTypeKeyWords
 */
func (this *GRule) MatchKeyWords(ruleContent *RuleContent) ([]*Match, string, bool) {
	inputData := this.FilePolicy.FileName
	matches, matched := matchKeyWords(ruleContent, this.FilePolicy.FileName)
	if !matched {
		inputData = this.FilePolicy.Content
		matches, matched = matchKeyWords(ruleContent, this.FilePolicy.Content)
	}
	return matches, inputData, matched
}

func matchKeyWords(ruleContent *RuleContent, inputData string) ([]*Match, bool) {
	exitReverse := len(ruleContent.ReverseKeyList) > 0
	if exitReverse {
		patterns := getKeyWordsPatterns(ruleContent.ReverseKeyList)
		if patterns == nil {
			return nil, false
		}
		gohs := &Gohs{Patterns: patterns}
		matches, err := gohs.Run(inputData)
		if err != nil {
			return nil, false
		}
		if len(matches) >= ruleContent.ReverseThreshold {
			return nil, false
		}
	}
	patterns := getKeyWordsPatterns(ruleContent.ForWardKeyList)
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

func getKeyWordsPatterns(keyWords []string) []*hyperscan.Pattern {
	var patterns []*hyperscan.Pattern
	for _, word := range keyWords {
		pattern := hyperscan.NewPattern(word, hyperscan.SomLeftMost|hyperscan.Utf8Mode)
		patterns = append(patterns, pattern)
	}
	return patterns
}
