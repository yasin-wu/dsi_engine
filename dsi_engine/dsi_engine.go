package dsi_engine

import (
	"errors"
	"fmt"
	"time"

	"github.com/yasin-wu/dsi_engine/consts"
	"github.com/yasin-wu/dsi_engine/policy"
	"github.com/yasin-wu/dsi_engine/regexp_engine"

	"github.com/hyperjumptech/grule-rule-engine/ast"
	"github.com/hyperjumptech/grule-rule-engine/builder"
	"github.com/hyperjumptech/grule-rule-engine/engine"
	"github.com/hyperjumptech/grule-rule-engine/pkg"
)

type DsiEngine struct {
	fingerRatio      int
	snapLength       int
	attachLength     int
	matchFuncName    string
	callbackFuncName string
	rule             string
	alarm            *policy.Alarm
	sensitiveData    *policy.SensitiveData
	policyInfo       *policy.Policy
	matches          []*regexp_engine.Match
	ruleSnaps        []*policy.RuleSnap
}

func New(sensitiveData *policy.SensitiveData) (*DsiEngine, error) {
	if sensitiveData == nil {
		return nil, errors.New("sensitiveData is nil")
	}
	return &DsiEngine{sensitiveData: sensitiveData}, nil
}

func (this *DsiEngine) SetFingerRatio(fingerRatio int) {
	this.fingerRatio = fingerRatio
}

func (this *DsiEngine) SetSnapLength(snapLength int) {
	this.snapLength = snapLength
}

func (this *DsiEngine) SetAttachLength(attachLength int) {
	this.attachLength = attachLength
}

func (this *DsiEngine) SetMatchFuncName(matchFuncName string) {
	this.matchFuncName = matchFuncName
}

func (this *DsiEngine) SetCallbackFuncName(callbackFuncName string) {
	this.callbackFuncName = callbackFuncName
}

func (this *DsiEngine) Run(policyInfo *policy.Policy) (*policy.Alarm, error) {
	if this.matchFuncName == "" {
		this.matchFuncName = consts.MatchFuncName
	}
	if this.callbackFuncName == "" {
		this.callbackFuncName = consts.CallbackFuncName
	}
	if this.attachLength == 0 {
		this.attachLength = consts.DefaultAttachLength
	}
	if this.snapLength == 0 {
		this.snapLength = consts.DefaultSnapLength
	}
	if policyInfo == nil {
		return nil, errors.New("policyInfo is nil")
	}
	this.policyInfo = policyInfo
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
	policyInfo := this.policyInfo
	rule := policyInfo.Rules[ruleIndex]
	ruleType := rule.Type
	matched := false
	inputData := ""
	distance := 100
	var matches []*regexp_engine.Match
	matchEngine := NewEngine(ruleType, this)
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
		if ruleType == consts.FingerDNA {
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
	policyInfo := this.policyInfo
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
			if operator == consts.And {
				patterns += fmt.Sprintf(` && %v(%d)`, this.matchFuncName, i+1)
			} else if operator == consts.Or {
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
	policyAlarm := &policy.Alarm{}
	sensitiveData := this.sensitiveData
	policyInfo := this.policyInfo
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
	policyAlarm.RuleSnaps = this.ruleSnaps
	policyAlarm.PolicyId = policyInfo.Id
	policyAlarm.FilePath = sensitiveData.FilePath
	policyAlarm.FileSize = sensitiveData.FileSize
	policyAlarm.FileName = sensitiveData.FileName
	policyAlarm.MatchTimes = matchTimes
	policyAlarm.SnapShot = snapShot
	policyAlarm.CreatedAt = now
	policyAlarm.AttachWords = sensitiveData.Content[0:this.attachLength]
	policyAlarm.MatchNote = this.handleMatchNote()
	policyAlarm.FingerRatio = this.fingerRatio
	return policyAlarm
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
