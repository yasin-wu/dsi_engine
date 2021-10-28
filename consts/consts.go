package consts

import "errors"

const (
	KeyWords   = 1
	FuzzyWords = 2
	Regexp     = 3
	FingerDNA  = 4
)

const (
	And = 0
	Or  = 1
)

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
