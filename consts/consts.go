package consts

import "errors"

const (
	GRuleName     = "DSIEngine"
	GRuleVersion  = "1.0.0"
	GRuleMaxCycle = 1
)

var (
	ErrParameterEmpty = errors.New("parameter is empty")
)

var (
	Red   = string([]byte{27, 91, 51, 49, 109})
	Reset = string([]byte{27, 91, 48, 109})
)
