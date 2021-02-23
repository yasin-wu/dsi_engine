package dlp

import (
	"errors"
	"fmt"
	"github.com/yasin-wu/dlp/consts"
	"github.com/yasin-wu/dlp/gohs"
	"github.com/yasin-wu/dlp/rule"
	"sort"
	"strconv"
	"time"

	js "github.com/bitly/go-simplejson"
	"github.com/flier/gohs/hyperscan"
)

type Inspect struct {
}

func (this *Inspect) Inspect(jsonBody *js.Json, allCheck bool) (*js.Json, error) {
	item, ok := jsonBody.CheckGet("item")
	if !ok {
		return nil, errors.New("not found item")
	}
	inputData, ok := item.CheckGet("value")
	if !ok {
		return nil, errors.New("not found item.value")
	}
	inspectConfig := js.New()
	if !allCheck {
		inspectConfig, ok = jsonBody.CheckGet("inspectConfig")
		if !ok {
			return nil, errors.New("not found inspectConfig")
		}
	}
	var patterns []*hyperscan.Pattern
	//infoTypes
	infoTypePatters := this.handleInfoTypes(inspectConfig)
	//customInfoTypes
	customInfoTypePatters := this.handleCustomInfoTypes(inspectConfig)
	//allCheck
	var allCheckTypes []*js.Json
	var allCheckPatters []*hyperscan.Pattern
	if allCheck {
		allCheckPatters, allCheckTypes = this.handleAllCheck()
		patterns = append(patterns, allCheckPatters...)
	}
	patterns = append(patterns, infoTypePatters...)
	patterns = append(patterns, customInfoTypePatters...)
	gohs := &gohs.Gohs{
		Patterns: patterns,
	}
	matches, err := gohs.Run(inputData.MustString())
	if err != nil {
		return nil, err
	}
	return this.handleInspect(matches, jsonBody, allCheckTypes), nil
}

/**
 * @author: yasin
 * @date: 2020/7/13 15:28
 * @description：1000
 */
func (this *Inspect) handleInfoTypes(inspectConfig *js.Json) []*hyperscan.Pattern {
	err := rule.InitRule()
	if err != nil {
		return nil
	}
	infoTypes, ok := inspectConfig.CheckGet("infoTypes")
	if !ok {
		return nil
	}
	var patterns []*hyperscan.Pattern
	for index := 0; ; index++ {
		infoType := infoTypes.GetIndex(index)
		if infoType.Interface() == nil {
			break
		}
		name := infoType.Get("name").MustString()
		pattern := hyperscan.NewPattern(rule.RulesMap[name].(map[string]interface{})["rule"].(string), hyperscan.SomLeftMost|hyperscan.Utf8Mode)
		id := fmt.Sprintf("%d%d", consts.InfoTypeID, index)
		pattern.Id, _ = strconv.Atoi(id)
		patterns = append(patterns, pattern)
	}
	return patterns
}

/**
 * @author: yasin
 * @date: 2020/7/13 15:28
 * @description：2000
 */
func (this *Inspect) handleCustomInfoTypes(inspectConfig *js.Json) []*hyperscan.Pattern {
	customInfoTypes, ok := inspectConfig.CheckGet("customInfoTypes")
	if !ok {
		return nil
	}
	var patterns []*hyperscan.Pattern
	for index := 0; ; index++ {
		infoType := customInfoTypes.GetIndex(index)
		if infoType.Interface() == nil {
			break
		}
		patternStr := infoType.GetPath("regex", "pattern").MustString()
		pattern := hyperscan.NewPattern(patternStr, hyperscan.SomLeftMost|hyperscan.Utf8Mode)
		id := fmt.Sprintf("%d%d", consts.CustomInfoTypeID, index)
		pattern.Id, _ = strconv.Atoi(id)
		patterns = append(patterns, pattern)
	}
	return patterns
}

/**
 * @author: yasin
 * @date: 2020/7/13 15:37
 * @description：
 */
func (this *Inspect) handleInspect(matches []*gohs.Match, jsonBody *js.Json, allCheckTypes []*js.Json) *js.Json {
	jsonObj := js.New()
	if matches == nil {
		return nil
	}
	var findings []*js.Json
	for _, m := range matches {
		finding := js.New()
		id := m.Id
		start := m.From
		end := m.To
		quote := m.InputData[start:end]

		finding.Set("quote", quote)
		finding.SetPath([]string{"infoType", "name"}, this.getInfoTypeName(id, jsonBody, allCheckTypes))
		finding.SetPath([]string{"location", "byteRange", "start"}, start)
		finding.SetPath([]string{"location", "byteRange", "end"}, end)
		finding.Set("createTime", time.Now())

		findings = append(findings, finding)
	}
	jsonObj.Set("findings", findings)
	return jsonObj
}

/**
 * @author: yasin
 * @date: 2020/8/18 16:21
 * @description：3000
 */
func (this *Inspect) handleAllCheck() ([]*hyperscan.Pattern, []*js.Json) {
	err := rule.InitRule()
	if err != nil {
		return nil, nil
	}
	var infoTypes []*js.Json
	for k, _ := range rule.RulesMap {
		jsonObj := js.New()
		jsonObj.Set("name", k)

		infoTypes = append(infoTypes, jsonObj)
	}
	var patterns []*hyperscan.Pattern
	for index := 0; index < len(infoTypes); index++ {
		infoType := infoTypes[index]
		name := infoType.Get("name").MustString()
		pattern := hyperscan.NewPattern(rule.RulesMap[name].(map[string]interface{})["rule"].(string), hyperscan.SomLeftMost|hyperscan.Utf8Mode)
		id := fmt.Sprintf("%d%d", consts.AllCheckID, index)
		pattern.Id, _ = strconv.Atoi(id)
		patterns = append(patterns, pattern)
	}
	return patterns, infoTypes
}

func (this *Inspect) getInfoTypeName(id uint, jsonBody *js.Json, allCheckTypes []*js.Json) string {
	idStr := fmt.Sprintf("%d", id)
	_typeInt, _ := strconv.Atoi(idStr[0:4])
	_indexInt, _ := strconv.Atoi(idStr[4:])
	infoTypeName := ""
	switch _typeInt {
	case consts.InfoTypeID:
		infoTypeName = jsonBody.GetPath("inspectConfig", "infoTypes").GetIndex(_indexInt).Get("name").MustString()
	case consts.CustomInfoTypeID:
		infoTypeName = jsonBody.GetPath("inspectConfig", "customInfoTypes").GetIndex(_indexInt).GetPath("infoType", "name").MustString()
	case consts.AllCheckID:
		infoTypeName = allCheckTypes[_indexInt].Get("name").MustString()
	default:
		infoTypeName = "unknown"
	}
	return infoTypeName
}

func (this *Inspect) InfoTypeList() []string {
	err := rule.InitRule()
	if err != nil {
		return nil
	}
	var infoTypes []string
	for k, _ := range rule.RulesMap {
		infoTypes = append(infoTypes, k)
	}
	sort.Strings(infoTypes)
	return infoTypes
}
