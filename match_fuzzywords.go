package models

import (
	"fmt"
	"github.com/flier/gohs/hyperscan"
	"strings"
)

/**
 * @author: yasin
 * @date: 2020/6/24 15:53
 * @description：RuleTypeFuzzyWords
 */
func (this *GRule) MatchFuzzyWords(ruleContent *RuleContent) ([]*Match, string, bool) {
	inputData := this.FilePolicy.FileName
	matches, matched := matchFuzzyWords(ruleContent, this.FilePolicy.FileName)
	if !matched {
		inputData = this.FilePolicy.Content
		matches, matched = matchFuzzyWords(ruleContent, this.FilePolicy.Content)
	}
	return matches, inputData, matched
}

func matchFuzzyWords(ruleContent *RuleContent, inputData string) ([]*Match, bool) {
	baseRegexp := ruleContent.BaseRegexp
	characterSpace := ruleContent.CharacterSpace
	patterns := getFuzzyWordsPatterns(baseRegexp, characterSpace)
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

//todo:正则存在问题,会出现pattern is too large
func getFuzzyWordsPatterns(baseRegexp, characterSpace string) []*hyperscan.Pattern {
	characterSpace = fmt.Sprintf(`.{0,%s}`, characterSpace)
	var patterns []*hyperscan.Pattern
	baseRegexpList := strings.Split(baseRegexp, ",")
	for _, b := range baseRegexpList {
		wordList := strings.Split(b, "")
		word := ""
		for _, w := range wordList {
			word += w + characterSpace
		}
		word = word[0:strings.LastIndex(word, characterSpace)]
		pattern := hyperscan.NewPattern(word, hyperscan.SomLeftMost|hyperscan.Utf8Mode)
		patterns = append(patterns, pattern)
	}
	return patterns
}
