// Code generated by "stringer -type RuleType -linecomment"; DO NOT EDIT.

package enum

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[KEYWORDS_RULETYPE-1]
	_ = x[FUZZYWORDS_RULETYPE-2]
	_ = x[REGEXP_RULETYPE-3]
	_ = x[FINGERDNA_RULETYPE-4]
}

const _RuleType_name = "关键字模糊关键字正则表达式文件指纹"

var _RuleType_index = [...]uint8{0, 9, 24, 39, 51}

func (i RuleType) String() string {
	i -= 1
	if i < 0 || i >= RuleType(len(_RuleType_index)-1) {
		return "RuleType(" + strconv.FormatInt(int64(i+1), 10) + ")"
	}
	return _RuleType_name[_RuleType_index[i]:_RuleType_index[i+1]]
}