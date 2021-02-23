package consts

const (
	RuleTypeKeyWords   = 1
	RuleTypeFuzzyWords = 2
	RuleTypeRegexp     = 3
	RuleTypeFingerDNA  = 4
)

const (
	RuleAnd = 0
	RuleOr  = 1
)

const (
	GRuleMatchFuncName    = "FileGRule.DoMatch"
	GRuleCallbackFuncName = "FileGRule.HandleResult"
)

const (
	DefaultSnapLength   = 100
	DefaultAttachLength = 1000
)

const (
	InfoTypeID       = 1000
	CustomInfoTypeID = 2000
	AllCheckID       = 3000
)

const (
	GRuleName     = "FileGRule"
	GRuleVersion  = "1.0.0"
	GRuleMaxCycle = 1
)
