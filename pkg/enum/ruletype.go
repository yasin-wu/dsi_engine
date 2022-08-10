//go:generate stringer -type RuleType -linecomment
package enum

type RuleType int

const (
	_                  RuleType = iota
	KeywordsRuletype            // 关键字
	FuzzywordsRuletype          // 模糊关键字
	RegexpRuletype              // 正则表达式
	FingerdnaRuletype           // 指纹相似度
)
