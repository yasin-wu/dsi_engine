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

/**
 * @author: yasinWu
 * @date: 2022/1/13 13:27
 * @description: DsiEngine配置项选择器
 */
type Option func(dsiEngine *DsiEngine)

/**
 * @author: yasinWu
 * @date: 2022/1/13 13:28
 * @description: DsiEngine Client
 */
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

/**
 * @author: yasinWu
 * @date: 2022/1/13 13:28
 * @params: options ...Option
 * @return: *DsiEngine
 * @description: 新建DsiEngine Client
 */
func New(options ...Option) *DsiEngine {
	dsiEngine := &DsiEngine{
		matchFuncName:    consts.MatchFuncName,
		callbackFuncName: consts.CallbackFuncName,
	}
	for _, f := range options {
		f(dsiEngine)
	}
	if dsiEngine.attachLength == 0 {
		dsiEngine.attachLength = consts.DefaultAttachLength
	}
	if dsiEngine.snapLength == 0 {
		dsiEngine.snapLength = consts.DefaultSnapLength
	}
	return dsiEngine
}

/**
 * @author: yasinWu
 * @date: 2022/1/13 13:29
 * @params: fingerRatio int
 * @return: Option
 * @description: 配置指纹相似度
 */
func WithFingerRatio(fingerRatio int) Option {
	return func(dsiEngine *DsiEngine) {
		dsiEngine.fingerRatio = fingerRatio
	}
}

/**
 * @author: yasinWu
 * @date: 2022/1/13 13:30
 * @params: snapLength int
 * @return: Option
 * @description: 配置告警信息快照长度
 */
func WithSnapLength(snapLength int) Option {
	return func(dsiEngine *DsiEngine) {
		dsiEngine.snapLength = snapLength
	}
}

/**
 * @author: yasinWu
 * @date: 2022/1/13 13:30
 * @params: attachLength int
 * @return: Option
 * @description: 配置附件信息长度
 */
func WithAttachLength(attachLength int) Option {
	return func(dsiEngine *DsiEngine) {
		dsiEngine.attachLength = attachLength
	}
}

/**
 * @author: yasinWu
 * @date: 2022/1/13 13:32
 * @params: sensitiveData *policy.SensitiveData
 * @return: []*policy.Alarm, error
 * @description: 运行检测
 */
func (d *DsiEngine) Run(sensitiveData *policy.SensitiveData) ([]*policy.Alarm, error) {
	if sensitiveData == nil {
		return nil, errors.New("sensitive data is nil")
	}
	var err error
	var errMsg string
	var alarms []*policy.Alarm
	d.sensitiveData = sensitiveData
	for _, policyInfo := range d.sensitiveData.Policies {
		alarm, err := d.run(policyInfo)
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

func (d *DsiEngine) run(policyInfo *policy.Policy) (*policy.Alarm, error) {
	if policyInfo == nil {
		return nil, errors.New("policyInfo is nil")
	}
	d.policy = policyInfo
	rule, err := d.handlePolicy()
	if err != nil {
		return nil, err
	}
	dataContext := ast.NewDataContext()
	err = dataContext.Add("Engine", d)
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
	return d.alarm, nil
}

func (d *DsiEngine) DoMatch(ruleIndex int64) bool {
	policyInfo := d.policy
	rule := policyInfo.Rules[ruleIndex]
	ruleType := rule.Type
	matched := false
	inputData := ""
	distance := 100
	var matches []*regexp_engine.Match
	matchEngine := NewEngine(ruleType, d)
	if matchEngine == nil {
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
		ruleSnap.Snap = d.handleSnap(matches, inputData)
		d.ruleSnaps = append(d.ruleSnaps, ruleSnap)
		if ruleType == enum.FINGERDNA_RULETYPE {
			distance = matches[0].Distance
			d.fingerRatio = distance
		}
	}
	return matched
}

func (d *DsiEngine) HandleResult() {
	d.alarm = d.handlePolicyAlarm()
}

func (d *DsiEngine) handlePolicy() (string, error) {
	policyInfo := d.policy
	if len(policyInfo.Rules) != len(policyInfo.Operators)+1 {
		return "", errors.New("policyInfo.Rules Or policyInfo.Operators Format Error ")
	}
	patterns := ""
	if len(policyInfo.Operators) == 0 {
		patterns = fmt.Sprintf(` %s(%d) `, d.matchFuncName, 0)
	} else {
		for i := 0; i < len(policyInfo.Operators); i++ {
			operator := policyInfo.Operators[i]
			if i == 0 {
				patterns = fmt.Sprintf(`%s(%d) `, d.matchFuncName, i)
			}
			if operator == enum.AND_OPERATOR {
				patterns += fmt.Sprintf(` && %s(%d) `, d.matchFuncName, i+1)
			} else if operator == enum.OR_OPERATOR {
				patterns += fmt.Sprintf(` || %s(%d) `, d.matchFuncName, i+1)
			}
		}
	}
	d.rule = fmt.Sprintf(`rule Check "Check" { when %s then %s(); Retract("Check"); }`, patterns, d.callbackFuncName)
	return d.rule, nil
}

func (d *DsiEngine) handlePolicyAlarm() *policy.Alarm {
	alarm := &policy.Alarm{}
	sensitiveData := d.sensitiveData
	policyInfo := d.policy
	matchTimes := 0
	snapShot := ""
	now := time.Now()
	for _, rs := range d.ruleSnaps {
		matchTimes += rs.MatchTimes
		snapShot += rs.Snap
	}
	if d.attachLength > len(sensitiveData.Content) {
		d.attachLength = len(sensitiveData.Content)
	}
	alarm.RuleSnaps = d.ruleSnaps
	alarm.PolicyId = policyInfo.Id
	alarm.FileName = sensitiveData.FileName
	alarm.FileType = sensitiveData.FileType
	alarm.FilePath = sensitiveData.FilePath
	alarm.FileSize = sensitiveData.FileSize
	alarm.MatchTimes = matchTimes
	alarm.SnapShot = snapShot
	alarm.CreatedAt = now
	alarm.AttachWords = sensitiveData.Content[0:d.attachLength]
	alarm.MatchNote = d.handleMatchNote()
	alarm.FingerRatio = d.fingerRatio
	return alarm
}

func (d *DsiEngine) handleSnap(matches []*regexp_engine.Match, inputData string) string {
	snap := ""
	snapLength := uint64(d.snapLength)
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
			d.highlight(inputData[from:to]),
			inputData[to:end]) + "......"
		match.InputData = inputData
		d.matches = append(d.matches, match)
	}

	return snap
}

func (d *DsiEngine) highlight(s string) string {
	return `<b style="background:red">` + s + `</b>`
	//return fmt.Sprintf("%s%s%s", consts.Red, s, consts.Reset)
	//return "\033[35m" + s + "\033[0m"
}

func (d *DsiEngine) handleMatchNote() string {
	matchNote := ""
	matchNoteMap := make(map[string]int)
	for _, m := range d.matches {
		key := m.InputData[m.From:m.To]
		matchNoteMap[key] += 1
	}
	for k, v := range matchNoteMap {
		matchNote += fmt.Sprintf("%s:%d", k, v)
	}
	return matchNote
}
