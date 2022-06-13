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
	case enum.KEYWORDS_RULETYPE:
		return &keyWords{}, nil
	case enum.FUZZYWORDS_RULETYPE:
		return &fuzzyWords{}, nil
	case enum.REGEXP_RULETYPE:
		return &regexp{}, nil
	case enum.FINGERDNA_RULETYPE:
		return &fingerPrint{}, nil
	default:
		return nil, errors.New("not supported rule type")
	}
}
