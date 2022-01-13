//go:generate stringer -type RuleType -linecomment
package enum

type RuleType int

const (
	_                   RuleType = iota
	KEYWORDS_RULETYPE            //关键字
	FUZZYWORDS_RULETYPE          //模糊关键字
	REGEXP_RULETYPE              //正则表达式
	FINGERDNA_RULETYPE           //指纹相似度
)
