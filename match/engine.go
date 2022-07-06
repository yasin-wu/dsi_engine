package match

import (
	"errors"

	"github.com/yasin-wu/dsi_engine/v2/entity"
	"github.com/yasin-wu/dsi_engine/v2/enum"
)

type Engine interface {
	Match(rule entity.Rule, sensitiveData entity.SensitiveData) ([]*entity.Match, string, bool)
}

func New(ruleType enum.RuleType) (Engine, error) {
	switch ruleType {
	case enum.KeywordsRuletype:
		return &keyWords{}, nil
	case enum.FuzzywordsRuletype:
		return &fuzzyWords{}, nil
	case enum.RegexpRuletype:
		return &regexp{}, nil
	case enum.FingerdnaRuletype:
		return &fingerPrint{wordRatio: 0.05}, nil
	default:
		return nil, errors.New("not supported rule type")
	}
}
