package dlp

import (
	"errors"
	"fmt"
	"github.com/hyperjumptech/grule-rule-engine/ast"
	"github.com/hyperjumptech/grule-rule-engine/builder"
	"github.com/hyperjumptech/grule-rule-engine/engine"
	"github.com/hyperjumptech/grule-rule-engine/pkg"
	"time"
)

type GRule struct {
	FilePolicy       *FilePolicy
	PolicyInfo       *PolicyInfo
	PolicyAlarm      *PolicyAlarm
	Matches          []*Match
	RuleSnaps        []*RuleSnap
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
		this.MatchFuncName = GRuleMatchFuncName
	}
	if this.CallbackFuncName == "" {
		this.CallbackFuncName = GRuleCallbackFuncName
	}
	if this.AttachLength == 0 {
		this.AttachLength = DefaultAttachLength
	}
	if this.SnapLength == 0 {
		this.SnapLength = DefaultSnapLength
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
	memory := ast.NewWorkingMemory()
	knowledgeBase := ast.NewKnowledgeBase("FileGRule", "0.1.1")
	ruleBuilder := builder.NewRuleBuilder(knowledgeBase, memory)

	err = ruleBuilder.BuildRuleFromResource(pkg.NewBytesResource([]byte(rule)))
	if err != nil {
		return errors.New(fmt.Sprintf("ruleBuilder.BuildRuleFromResource err: %v", err.Error()))
	} else {
		eng := &engine.GruleEngine{MaxCycle: 1}
		err = eng.Execute(dataContext, knowledgeBase, memory)
		if err != nil {
			return errors.New(fmt.Sprintf("eng.Execute err: %v", err.Error()))
		} else {
			fmt.Println("GRule run end......")
			return nil
		}
	}
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
	var matches []*Match
	distance := 100
	switch ruleType {
	case RuleTypeKeyWords:
		matches, inputData, matched = this.MatchKeyWords(ruleContent)
	case RuleTypeFuzzyWords:
		matches, inputData, matched = this.MatchFuzzyWords(ruleContent)
	case RuleTypeRegexp:
		matches, inputData, matched = this.MatchRegexp(ruleContent)
	case RuleTypeFingerDNA:
		distance, inputData, matched = this.MatchFinger()
	default:
	}
	if matched {
		ruleSnap := &RuleSnap{}
		ruleSnap.RuleId = ruleContent.RuleId
		ruleSnap.RuleName = ruleContent.RuleName
		ruleSnap.RuleType = ruleType
		ruleSnap.MatchTimes = len(matches)
		ruleSnap.Level = ruleContent.Level
		ruleSnap.LevelName = ruleContent.RuleName
		ruleSnap.Snap = this.handleSnap(matches, inputData)
		this.RuleSnaps = append(this.RuleSnaps, ruleSnap)
		if ruleType == RuleTypeFingerDNA {
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
			if operator == RuleAnd {
				patterns += fmt.Sprintf(` && %v(%d)`, this.MatchFuncName, i+1)
			} else if operator == RuleOr {
				patterns += fmt.Sprintf(` || %v(%d)`, this.MatchFuncName, i+1)
			}
		}
	}
	rule := fmt.Sprintf(`rule FileCheck "fileCheck" { when %v then %v; }`, patterns, this.CallbackFuncName+"()")
	this.Rule = rule
	return rule, nil
}

/**
 * @author: yasin
 * @date: 2020/6/28 13:44
 * @description：handle policyAlarm
 */
func (this *GRule) handlePolicyAlarm() *PolicyAlarm {
	policyAlarm := &PolicyAlarm{}
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

func (this *GRule) handleSnap(matches []*Match, inputData string) string {
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
			highlight(inputData[from:to]),
			inputData[to:end]) + "......"
		match.InputData = inputData
		this.Matches = append(this.Matches, match)
	}

	return snap
}

func highlight(s string) string {
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
