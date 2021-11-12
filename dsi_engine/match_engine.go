package dsi_engine

import (
	"github.com/yasin-wu/dsi_engine/v2/consts"
	"github.com/yasin-wu/dsi_engine/v2/policy"
	"github.com/yasin-wu/dsi_engine/v2/regexp_engine"
)

type MatchEngine interface {
	match(rule *policy.Rule) ([]*regexp_engine.Match, string, bool)
}

func NewEngine(ruleType int, dsiEngine *DsiEngine) MatchEngine {
	switch ruleType {
	case consts.KeyWords:
		return &KeyWords{dsiEngine: dsiEngine}
	case consts.FuzzyWords:
		return &FuzzyWords{dsiEngine: dsiEngine}
	case consts.Regexp:
		return &Regexp{dsiEngine: dsiEngine}
	case consts.FingerDNA:
		return &FingerPrint{dsiEngine: dsiEngine}
	default:
		return nil
	}
}
