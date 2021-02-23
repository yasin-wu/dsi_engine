package grule

import (
	"errors"
	"fmt"
	"github.com/yasin-wu/dlp/consts"
	"github.com/yasin-wu/dlp/gohs"
	"github.com/yasin-wu/dlp/policy"
	"time"

	"github.com/hyperjumptech/grule-rule-engine/ast"
	"github.com/hyperjumptech/grule-rule-engine/builder"
	"github.com/hyperjumptech/grule-rule-engine/engine"
	"github.com/hyperjumptech/grule-rule-engine/pkg"
)

type GRule struct {
	FilePolicy       *policy.FilePolicy
	PolicyInfo       *policy.PolicyInfo
	PolicyAlarm      *policy.PolicyAlarm
	Matches          []*gohs.Match
	RuleSnaps        []*policy.RuleSnap
	FingerRatio      int
	Rule             string
	MatchFuncName    string
	CallbackFuncName string
	SnapLength       int
	AttachLength     int
}

/**
 * @author: yasin
 * @date: 2020/6/28 13:42
 * @description：main func
 */
func (this *GRule) RunFileCheck() error {
	if this.MatchFuncName == "" {
		this.MatchFuncName = consts.GRuleMatchFuncName
	}
	if this.CallbackFuncName == "" {
		this.CallbackFuncName = consts.GRuleCallbackFuncName
	}
	if this.AttachLength == 0 {
		this.AttachLength = consts.DefaultAttachLength
	}
	if this.SnapLength == 0 {
		this.SnapLength = consts.DefaultSnapLength
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

/**
 * @author: yasin
 * @date: 2020/6/28 13:43
 * @description：one match func
 */
func (this *GRule) DoMatch(ruleContentIndex int64) bool {
	policyInfo := this.PolicyInfo
	ruleContent := policyInfo.RuleContents[ruleContentIndex]
	ruleType := ruleContent.RuleType
	matched := false
	inputData := ""
	var matches []*gohs.Match
	distance := 100
	switch ruleType {
	case consts.RuleTypeKeyWords:
		matches, inputData, matched = this.MatchKeyWords(ruleContent)
	case consts.RuleTypeFuzzyWords:
		matches, inputData, matched = this.MatchFuzzyWords(ruleContent)
	case consts.RuleTypeRegexp:
		matches, inputData, matched = this.MatchRegexp(ruleContent)
	case consts.RuleTypeFingerDNA:
		distance, inputData, matched = this.MatchFinger()
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
		this.RuleSnaps = append(this.RuleSnaps, ruleSnap)
		if ruleType == consts.RuleTypeFingerDNA {
			this.FingerRatio = distance
		}
	}
	return matched
}

/**
 * @author: yasin
 * @date: 2020/6/28 13:43
 * @description：callback func
 */
func (this *GRule) HandleResult() {
	this.PolicyAlarm = this.handlePolicyAlarm()
}

/**
 * @author: yasin
 * @date: 2020/6/28 13:43
 * @description：handle policy
 */
func (this *GRule) handlePolicy() (string, error) {
	policyInfo := this.PolicyInfo
	if len(policyInfo.RuleContents) != len(policyInfo.Operators)+1 {
		return "", errors.New("policyInfo.RuleContents Or policyInfo.Operators Format Error ")
	}
	patterns := ""
	if len(policyInfo.Operators) == 0 {
		patterns = fmt.Sprintf(`%v(%d)`, this.MatchFuncName, 0)
	} else {
		for i := 0; i < len(policyInfo.Operators); i++ {
			operator := policyInfo.Operators[i]
			if i == 0 {
				patterns = fmt.Sprintf(`%v(%d)`, this.MatchFuncName, i)
			}
			if operator == consts.RuleAnd {
				patterns += fmt.Sprintf(` && %v(%d)`, this.MatchFuncName, i+1)
			} else if operator == consts.RuleOr {
				patterns += fmt.Sprintf(` || %v(%d)`, this.MatchFuncName, i+1)
			}
		}
	}
	rule := fmt.Sprintf(`rule FileCheck "fileCheck" { when %v then %v; %v; }`, patterns, this.CallbackFuncName+"()", `Retract("FileCheck")`)
	this.Rule = rule
	return rule, nil
}

/**
 * @author: yasin
 * @date: 2020/6/28 13:44
 * @description：handle policyAlarm
 */
func (this *GRule) handlePolicyAlarm() *policy.PolicyAlarm {
	policyAlarm := &policy.PolicyAlarm{}
	filePolicy := this.FilePolicy
	policyInfo := this.PolicyInfo
	matchTimes := 0
	snapShot := ""
	now := time.Now()
	for _, rs := range this.RuleSnaps {
		matchTimes += rs.MatchTimes
		snapShot += rs.Snap
	}
	if this.AttachLength > len(filePolicy.Content) {
		this.AttachLength = len(filePolicy.Content)
	}
	policyAlarm.RuleSnaps = this.RuleSnaps
	policyAlarm.PolicyId = policyInfo.PolicyId
	policyAlarm.FilePath = filePolicy.FilePath
	policyAlarm.FileSize = filePolicy.FileSize
	policyAlarm.FileName = filePolicy.FileName
	policyAlarm.MatchTimes = matchTimes
	policyAlarm.SnapShot = snapShot
	policyAlarm.CreatedAt = now
	policyAlarm.AttachWords = filePolicy.Content[0:this.AttachLength]
	policyAlarm.MatchNote = this.handleMatchNote()
	policyAlarm.FingerRatio = this.FingerRatio
	return policyAlarm
}

func (this *GRule) handleSnap(matches []*gohs.Match, inputData string) string {
	snap := ""
	snapLength := uint64(this.SnapLength)
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
		this.Matches = append(this.Matches, match)
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
	for _, m := range this.Matches {
		key := m.InputData[m.From:m.To]
		matchNoteMap[key] += 1
	}
	for k, v := range matchNoteMap {
		matchNote += fmt.Sprintf("%s:%d", k, v)
	}
	return matchNote
}
