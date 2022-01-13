package dsi_engine

import (
	"github.com/yasin-wu/dsi_engine/v2/enum"
	"github.com/yasin-wu/dsi_engine/v2/policy"
	"github.com/yasin-wu/dsi_engine/v2/regexp_engine"
)

type matchEngine interface {
	match(rule *policy.Rule) ([]*regexp_engine.Match, string, bool)
}

func NewEngine(ruleType enum.RuleType, dsiEngine *DsiEngine) matchEngine {
	switch ruleType {
	case enum.KEYWORDS_RULETYPE:
		return &keyWords{dsiEngine: dsiEngine}
	case enum.FUZZYWORDS_RULETYPE:
		return &fuzzyWords{dsiEngine: dsiEngine}
	case enum.REGEXP_RULETYPE:
		return &regexp{dsiEngine: dsiEngine}
	case enum.FINGERDNA_RULETYPE:
		return &fingerPrint{dsiEngine: dsiEngine}
	default:
		return nil
	}
}
