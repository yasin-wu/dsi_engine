package grule

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/yasin-wu/dlp/consts"
	"github.com/yasin-wu/dlp/gohs"
	"github.com/yasin-wu/dlp/rule"

	js "github.com/bitly/go-simplejson"
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
	var regexps []*gohs.Regexp
	//infoTypes
	infoTypeRegexps := this.handleInfoTypes(inspectConfig)
	//customInfoTypes
	customInfoTypeRegexps := this.handleCustomInfoTypes(inspectConfig)
	//allCheck
	var allCheckTypes []*js.Json
	var allCheckRegexps []*gohs.Regexp
	if allCheck {
		allCheckRegexps, allCheckTypes = this.handleAllCheck()
		regexps = append(regexps, allCheckRegexps...)
	}
	regexps = append(regexps, infoTypeRegexps...)
	regexps = append(regexps, customInfoTypeRegexps...)
	gohs, err := gohs.New(regexps...)
	if err != nil {
		return nil, err
	}
	matches, err := gohs.Run(inputData.MustString())
	if err != nil {
		return nil, err
	}
	return this.handleInspect(matches, jsonBody, allCheckTypes), nil
}

func (this *Inspect) handleInfoTypes(inspectConfig *js.Json) []*gohs.Regexp {
	err := rule.InitRule()
	if err != nil {
		return nil
	}
	infoTypes, ok := inspectConfig.CheckGet("infoTypes")
	if !ok {
		return nil
	}
	var regexps []*gohs.Regexp
	for index := 0; ; index++ {
		infoType := infoTypes.GetIndex(index)
		if infoType.Interface() == nil {
			break
		}
		name := infoType.Get("name").MustString()
		id := fmt.Sprintf("%d%d", consts.InfoTypeID, index)
		idInt, _ := strconv.Atoi(id)
		regexp := &gohs.Regexp{
			Id:     idInt,
			Regexp: rule.RulesMap[name].(map[string]interface{})["rule"].(string),
		}
		regexps = append(regexps, regexp)
	}
	return regexps
}

func (this *Inspect) handleCustomInfoTypes(inspectConfig *js.Json) []*gohs.Regexp {
	customInfoTypes, ok := inspectConfig.CheckGet("customInfoTypes")
	if !ok {
		return nil
	}
	var regexps []*gohs.Regexp
	for index := 0; ; index++ {
		infoType := customInfoTypes.GetIndex(index)
		if infoType.Interface() == nil {
			break
		}
		id := fmt.Sprintf("%d%d", consts.CustomInfoTypeID, index)
		idInt, _ := strconv.Atoi(id)
		regexp := &gohs.Regexp{
			Id:     idInt,
			Regexp: infoType.GetPath("regex", "pattern").MustString(),
		}
		regexps = append(regexps, regexp)
	}
	return regexps
}

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

func (this *Inspect) handleAllCheck() ([]*gohs.Regexp, []*js.Json) {
	err := rule.InitRule()
	if err != nil {
		return nil, nil
	}
	var infoTypes []*js.Json
	for k := range rule.RulesMap {
		jsonObj := js.New()
		jsonObj.Set("name", k)

		infoTypes = append(infoTypes, jsonObj)
	}
	var regexps []*gohs.Regexp
	for index := 0; index < len(infoTypes); index++ {
		infoType := infoTypes[index]
		name := infoType.Get("name").MustString()
		id := fmt.Sprintf("%d%d", consts.AllCheckID, index)
		idInt, _ := strconv.Atoi(id)
		regexp := &gohs.Regexp{
			Id:     idInt,
			Regexp: rule.RulesMap[name].(map[string]interface{})["rule"].(string),
		}
		regexps = append(regexps, regexp)
	}
	return regexps, infoTypes
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
	for k := range rule.RulesMap {
		infoTypes = append(infoTypes, k)
	}
	sort.Strings(infoTypes)
	return infoTypes
}
