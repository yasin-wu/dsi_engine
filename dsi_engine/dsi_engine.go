package dsi_engine

import (
	"errors"
	"fmt"
	"time"

	"github.com/yasin-wu/dsi_engine/v2/enum"

	"github.com/yasin-wu/dsi_engine/v2/consts"
	"github.com/yasin-wu/dsi_engine/v2/policy"
	"github.com/yasin-wu/dsi_engine/v2/regexp_engine"

	"github.com/hyperjumptech/grule-rule-engine/ast"
	"github.com/hyperjumptech/grule-rule-engine/builder"
	"github.com/hyperjumptech/grule-rule-engine/engine"
	"github.com/hyperjumptech/grule-rule-engine/pkg"
)

type Option func(dsiEngine *DsiEngine)

type DsiEngine struct {
	fingerRatio      int
	snapLength       int
	attachLength     int
	matchFuncName    string
	callbackFuncName string
	rule             string
	alarm            *policy.Alarm
	sensitiveData    *policy.SensitiveData
	policy           *policy.Policy
	matches          []*regexp_engine.Match
	ruleSnaps        []*policy.RuleSnap
}

func New(sensitiveData *policy.SensitiveData, options ...Option) (*DsiEngine, error) {
	if sensitiveData == nil {
		return nil, errors.New("sensitiveData is nil")
	}
	dsiEngine := &DsiEngine{sensitiveData: sensitiveData}
	for _, f := range options {
		f(dsiEngine)
	}
	if dsiEngine.matchFuncName == "" {
		dsiEngine.matchFuncName = consts.MatchFuncName
	}
	if dsiEngine.callbackFuncName == "" {
		dsiEngine.callbackFuncName = consts.CallbackFuncName
	}
	if dsiEngine.attachLength == 0 {
		dsiEngine.attachLength = consts.DefaultAttachLength
	}
	if dsiEngine.snapLength == 0 {
		dsiEngine.snapLength = consts.DefaultSnapLength
	}
	return dsiEngine, nil
}

func WithFingerRatio(fingerRatio int) Option {
	return func(dsiEngine *DsiEngine) {
		dsiEngine.fingerRatio = fingerRatio
	}
}

func WithSnapLength(snapLength int) Option {
	return func(dsiEngine *DsiEngine) {
		dsiEngine.snapLength = snapLength
	}
}

func WithAttachLength(attachLength int) Option {
	return func(dsiEngine *DsiEngine) {
		dsiEngine.attachLength = attachLength
	}
}

func WithMatchFuncName(matchFuncName string) Option {
	return func(dsiEngine *DsiEngine) {
		dsiEngine.matchFuncName = matchFuncName
	}
}

func WithCallbackFuncName(callbackFuncName string) Option {
	return func(dsiEngine *DsiEngine) {
		dsiEngine.callbackFuncName = callbackFuncName
	}
}

func (this *DsiEngine) Run() ([]*policy.Alarm, error) {
	var err error
	var errMsg string
	var alarms []*policy.Alarm
	for _, policyInfo := range this.sensitiveData.Policies {
		alarm, err := this.run(policyInfo)
		if err != nil {
			errMsg += fmt.Sprintf("run err:%s;", err.Error())
			continue
		}
		alarm.Id = fmt.Sprintf("alarm-%s", policyInfo.Id)
		alarms = append(alarms, alarm)
	}
	if len(errMsg) > 0 {
		err = errors.New(errMsg)
	}
	return alarms, err
}

func (this *DsiEngine) run(policyInfo *policy.Policy) (*policy.Alarm, error) {
	if policyInfo == nil {
		return nil, errors.New("policyInfo is nil")
	}
	this.policy = policyInfo
	rule, err := this.handlePolicy()
	if err != nil {
		return nil, err
	}
	dataContext := ast.NewDataContext()
	err = dataContext.Add("Engine", this)
	if err != nil {
		return nil, fmt.Errorf("dataContext.Add err: %v", err.Error())
	}
	lib := ast.NewKnowledgeLibrary()
	ruleBuilder := builder.NewRuleBuilder(lib)
	ruleResource := pkg.NewBytesResource([]byte(rule))
	err = ruleBuilder.BuildRuleFromResource(consts.GRuleName, consts.GRuleVersion, ruleResource)
	if err != nil {
		return nil, fmt.Errorf("ruleBuilder.BuildRuleFromResource err: %v", err.Error())
	}
	kb := lib.NewKnowledgeBaseInstance(consts.GRuleName, consts.GRuleVersion)
	eng := &engine.GruleEngine{MaxCycle: consts.GRuleMaxCycle}
	err = eng.Execute(dataContext, kb)
	if err != nil {
		return nil, fmt.Errorf("eng.Execute err: %v", err.Error())
	}
	return this.alarm, nil
}

func (this *DsiEngine) DoMatch(ruleIndex int64) bool {
	policyInfo := this.policy
	rule := policyInfo.Rules[ruleIndex]
	ruleType := rule.Type
	matched := false
	inputData := ""
	distance := 100
	var matches []*regexp_engine.Match
	matchEngine := NewEngine(enum.RuleType(ruleType), this)
	if matchEngine == nil {
		fmt.Println("rule type is error")
		return false
	}
	matches, inputData, matched = matchEngine.match(rule)
	if matched {
		ruleSnap := &policy.RuleSnap{}
		ruleSnap.Id = rule.Id
		ruleSnap.Name = rule.Name
		ruleSnap.Type = ruleType
		ruleSnap.MatchTimes = len(matches)
		ruleSnap.Level = rule.Level
		ruleSnap.Snap = this.handleSnap(matches, inputData)
		this.ruleSnaps = append(this.ruleSnaps, ruleSnap)
		if ruleType == enum.FINGERDNA_RULETYPE {
			distance = matches[0].Distance
			this.fingerRatio = distance
		}
	}
	return matched
}

func (this *DsiEngine) HandleResult() {
	this.alarm = this.handlePolicyAlarm()
}

func (this *DsiEngine) handlePolicy() (string, error) {
	policyInfo := this.policy
	if len(policyInfo.Rules) != len(policyInfo.Operators)+1 {
		return "", errors.New("policyInfo.Rules Or policyInfo.Operators Format Error ")
	}
	patterns := ""
	if len(policyInfo.Operators) == 0 {
		patterns = fmt.Sprintf(`%v(%d)`, this.matchFuncName, 0)
	} else {
		for i := 0; i < len(policyInfo.Operators); i++ {
			operator := policyInfo.Operators[i]
			if i == 0 {
				patterns = fmt.Sprintf(`%v(%d)`, this.matchFuncName, i)
			}
			if operator == enum.AND_OPERATOR {
				patterns += fmt.Sprintf(` && %v(%d)`, this.matchFuncName, i+1)
			} else if operator == enum.OR_OPERATOR {
				patterns += fmt.Sprintf(` || %v(%d)`, this.matchFuncName, i+1)
			}
		}
	}
	rule := fmt.Sprintf(`rule Check "Check" { when %v then %v; %v; }`,
		patterns, this.callbackFuncName+"()", `Retract("Check")`)
	this.rule = rule
	return rule, nil
}

func (this *DsiEngine) handlePolicyAlarm() *policy.Alarm {
	alarm := &policy.Alarm{}
	sensitiveData := this.sensitiveData
	policyInfo := this.policy
	matchTimes := 0
	snapShot := ""
	now := time.Now()
	for _, rs := range this.ruleSnaps {
		matchTimes += rs.MatchTimes
		snapShot += rs.Snap
	}
	if this.attachLength > len(sensitiveData.Content) {
		this.attachLength = len(sensitiveData.Content)
	}
	alarm.RuleSnaps = this.ruleSnaps
	alarm.PolicyId = policyInfo.Id
	alarm.FileName = sensitiveData.FileName
	alarm.FileType = sensitiveData.FileType
	alarm.FilePath = sensitiveData.FilePath
	alarm.FileSize = sensitiveData.FileSize
	alarm.MatchTimes = matchTimes
	alarm.SnapShot = snapShot
	alarm.CreatedAt = now
	alarm.AttachWords = sensitiveData.Content[0:this.attachLength]
	alarm.MatchNote = this.handleMatchNote()
	alarm.FingerRatio = this.fingerRatio
	return alarm
}

func (this *DsiEngine) handleSnap(matches []*regexp_engine.Match, inputData string) string {
	snap := ""
	snapLength := uint64(this.snapLength)
	inputDataLength := uint64(len(inputData))
	for _, match := range matches {
		start := match.From - snapLength
		if start > inputDataLength {
			start = 0
		}
		from := match.From
		to := match.To
		end := match.To + snapLength
		if end > inputDataLength {
			end = inputDataLength
		}
		snap += fmt.Sprintf("%s%s%s", inputData[start:from],
			this.highlight(inputData[from:to]),
			inputData[to:end]) + "......"
		match.InputData = inputData
		this.matches = append(this.matches, match)
	}

	return snap
}

func (this *DsiEngine) highlight(s string) string {
	return `<b style="background:red">` + s + `</b>`
	//return "\033[35m" + s + "\033[0m"
}

func (this *DsiEngine) handleMatchNote() string {
	matchNote := ""
	matchNoteMap := make(map[string]int)
	for _, m := range this.matches {
		key := m.InputData[m.From:m.To]
		matchNoteMap[key] += 1
	}
	for k, v := range matchNoteMap {
		matchNote += fmt.Sprintf("%s:%d", k, v)
	}
	return matchNote
}
