package consts

import "errors"

const (
	MatchFuncName    = "Engine.DoMatch"
	CallbackFuncName = "Engine.HandleResult"
)

const (
	DefaultSnapLength   = 100
	DefaultAttachLength = 1000
)

const (
	GRuleName     = "DSIEngine"
	GRuleVersion  = "1.0.0"
	GRuleMaxCycle = 1
)

var (
	ErrParameterEmpty = errors.New("parameter is empty")
)
