package grule

import (
	"errors"
	"fmt"
	"time"

	"github.com/yasin-wu/dlp/consts"
	"github.com/yasin-wu/dlp/gohs"
	"github.com/yasin-wu/dlp/policy"

	"github.com/hyperjumptech/grule-rule-engine/ast"
	"github.com/hyperjumptech/grule-rule-engine/builder"
	"github.com/hyperjumptech/grule-rule-engine/engine"
	"github.com/hyperjumptech/grule-rule-engine/pkg"
)

type GRule struct {
	PolicyAlarm *policy.PolicyAlarm

	fingerRatio      int
	snapLength       int
	attachLength     int
	matchFuncName    string
	callbackFuncName string
	rule             string
	filePolicy       *policy.FilePolicy
	policyInfo       *policy.PolicyInfo
	matches          []*gohs.Match
	ruleSnaps        []*policy.RuleSnap
}

func New(filePolicy *policy.FilePolicy, policyInfo *policy.PolicyInfo) (*GRule, error) {
	if filePolicy == nil {
		return nil, errors.New("filePolicy is nil")
	}
	if policyInfo == nil {
		return nil, errors.New("policyInfo is nil")
	}
	return &GRule{filePolicy: filePolicy, policyInfo: policyInfo}, nil
}

func (this *GRule) SetFingerRatio(fingerRatio int) {
	this.fingerRatio = fingerRatio
}

func (this *GRule) SetSnapLength(snapLength int) {
	this.snapLength = snapLength
}

func (this *GRule) SetAttachLength(attachLength int) {
	this.attachLength = attachLength
}

func (this *GRule) SetMatchFuncName(matchFuncName string) {
	this.matchFuncName = matchFuncName
}

func (this *GRule) SetCallbackFuncName(callbackFuncName string) {
	this.callbackFuncName = callbackFuncName
}

func (this *GRule) RunCheckFile() error {
	if this.matchFuncName == "" {
		this.matchFuncName = consts.GRuleMatchFuncName
	}
	if this.callbackFuncName == "" {
		this.callbackFuncName = consts.GRuleCallbackFuncName
	}
	if this.attachLength == 0 {
		this.attachLength = consts.DefaultAttachLength
	}
	if this.snapLength == 0 {
		this.snapLength = consts.DefaultSnapLength
	}
	rule, err := this.handlePolicy()
	if err != nil {
		return err
	}
	dataContext := ast.NewDataContext()
	err = dataContext.Add("FileGRule", this)
	if err != nil {
		return errors.New(fmt.Sprintf("dataContext.Add err: %v", err.Error()))
	}
	lib := ast.NewKnowledgeLibrary()
	ruleBuilder := builder.NewRuleBuilder(lib)
	ruleResource := pkg.NewBytesResource([]byte(rule))
	err = ruleBuilder.BuildRuleFromResource(consts.GRuleName, consts.GRuleVersion, ruleResource)
	if err != nil {
		return errors.New(fmt.Sprintf("ruleBuilder.BuildRuleFromResource err: %v", err.Error()))
	}
	kb := lib.NewKnowledgeBaseInstance(consts.GRuleName, consts.GRuleVersion)
	eng := &engine.GruleEngine{MaxCycle: consts.GRuleMaxCycle}
	err = eng.Execute(dataContext, kb)
	if err != nil {
		return errors.New(fmt.Sprintf("eng.Execute err: %v", err.Error()))
	}
	fmt.Println("RunFileCheck end......")
	return nil
}

func (this *GRule) DoMatch(ruleContentIndex int64) bool {
	policyInfo := this.policyInfo
	ruleContent := policyInfo.RuleContents[ruleContentIndex]
	ruleType := ruleContent.RuleType
	matched := false
	inputData := ""
	var matches []*gohs.Match
	distance := 100
	switch ruleType {
	case consts.RuleTypeKeyWords:
		matches, inputData, matched = this.matchKeyWords(ruleContent)
	case consts.RuleTypeFuzzyWords:
		matches, inputData, matched = this.matchFuzzyWords(ruleContent)
	case consts.RuleTypeRegexp:
		matches, inputData, matched = this.matchRegexp(ruleContent)
	case consts.RuleTypeFingerDNA:
		distance, inputData, matched = this.matchFinger()
	default:
	}
	if matched {
		ruleSnap := &policy.RuleSnap{}
		ruleSnap.RuleId = ruleContent.RuleId
		ruleSnap.RuleName = ruleContent.RuleName
		ruleSnap.RuleType = ruleType
		ruleSnap.MatchTimes = len(matches)
		ruleSnap.Level = ruleContent.Level
		ruleSnap.LevelName = ruleContent.RuleName
		ruleSnap.Snap = this.handleSnap(matches, inputData)
		this.ruleSnaps = append(this.ruleSnaps, ruleSnap)
		if ruleType == consts.RuleTypeFingerDNA {
			this.fingerRatio = distance
		}
	}
	return matched
}

func (this *GRule) HandleResult() {
	this.PolicyAlarm = this.handlePolicyAlarm()
}

func (this *GRule) handlePolicy() (string, error) {
	policyInfo := this.policyInfo
	if len(policyInfo.RuleContents) != len(policyInfo.Operators)+1 {
		return "", errors.New("policyInfo.RuleContents Or policyInfo.Operators Format Error ")
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
			if operator == consts.RuleAnd {
				patterns += fmt.Sprintf(` && %v(%d)`, this.matchFuncName, i+1)
			} else if operator == consts.RuleOr {
				patterns += fmt.Sprintf(` || %v(%d)`, this.matchFuncName, i+1)
			}
		}
	}
	rule := fmt.Sprintf(`rule FileCheck "fileCheck" { when %v then %v; %v; }`, patterns, this.callbackFuncName+"()", `Retract("FileCheck")`)
	this.rule = rule
	return rule, nil
}

func (this *GRule) handlePolicyAlarm() *policy.PolicyAlarm {
	policyAlarm := &policy.PolicyAlarm{}
	filePolicy := this.filePolicy
	policyInfo := this.policyInfo
	matchTimes := 0
	snapShot := ""
	now := time.Now()
	for _, rs := range this.ruleSnaps {
		matchTimes += rs.MatchTimes
		snapShot += rs.Snap
	}
	if this.attachLength > len(filePolicy.Content) {
		this.attachLength = len(filePolicy.Content)
	}
	policyAlarm.RuleSnaps = this.ruleSnaps
	policyAlarm.PolicyId = policyInfo.PolicyId
	policyAlarm.FilePath = filePolicy.FilePath
	policyAlarm.FileSize = filePolicy.FileSize
	policyAlarm.FileName = filePolicy.FileName
	policyAlarm.MatchTimes = matchTimes
	policyAlarm.SnapShot = snapShot
	policyAlarm.CreatedAt = now
	policyAlarm.AttachWords = filePolicy.Content[0:this.attachLength]
	policyAlarm.MatchNote = this.handleMatchNote()
	policyAlarm.FingerRatio = this.fingerRatio
	return policyAlarm
}

func (this *GRule) handleSnap(matches []*gohs.Match, inputData string) string {
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

func (this *GRule) highlight(s string) string {
	return `<b style="background:yellow">` + s + `</b>`
	//return "\033[35m" + s + "\033[0m"
}

func (this *GRule) handleMatchNote() string {
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
