package dlp

import (
	"errors"
	"fmt"
	js "github.com/bitly/go-simplejson"
	"github.com/flier/gohs/hyperscan"
	"strconv"
	"time"
)

func Inspect(jsonBody *js.Json) (*js.Json, error) {
	item, ok := jsonBody.CheckGet("item")
	if !ok {
		return nil, errors.New("not found item")
	}
	inputData, ok := item.CheckGet("value")
	if !ok {
		return nil, errors.New("not found item.value")
	}
	inspectConfig, ok := jsonBody.CheckGet("inspectConfig")
	if !ok {
		return nil, errors.New("not found inspectConfig")
	}
	var patterns []*hyperscan.Pattern
	//infoTypes
	infoTypePatters := handleInfoTypes(inspectConfig)
	//customInfoTypes
	customInfoTypePatters := handleCustomInfoTypes(inspectConfig)
	patterns = append(patterns, infoTypePatters...)
	patterns = append(patterns, customInfoTypePatters...)
	gohs := &Gohs{
		Patterns: patterns,
	}
	matches, err := gohs.Run(inputData.MustString())
	if err != nil {
		return nil, err
	}
	return handleInspect(matches, jsonBody), nil
}

/**
 * @author: yasin
 * @date: 2020/7/13 15:28
 * @description：1000
 */
func handleInfoTypes(inspectConfig *js.Json) []*hyperscan.Pattern {
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
		pattern := hyperscan.NewPattern(InfoTypeMaps[name], hyperscan.SomLeftMost|hyperscan.Utf8Mode)
		id := fmt.Sprintf("%d%d", InfoTypeID, index)
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
func handleCustomInfoTypes(inspectConfig *js.Json) []*hyperscan.Pattern {
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
		id := fmt.Sprintf("%d%d", CustomInfoTypeID, index)
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
func handleInspect(matches []*Match, jsonBody *js.Json) *js.Json {
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
		finding.SetPath([]string{"infoType", "name"}, getInfoTypeName(id, jsonBody))
		finding.SetPath([]string{"location", "byteRange", "start"}, start)
		finding.SetPath([]string{"location", "byteRange", "end"}, end)
		finding.Set("createTime", time.Now())

		findings = append(findings, finding)
	}
	jsonObj.Set("result", findings)
	return jsonObj
}

func getInfoTypeName(id uint, jsonBody *js.Json) string {
	idStr := fmt.Sprintf("%d", id)
	_typeInt, _ := strconv.Atoi(idStr[0:4])
	_indexInt, _ := strconv.Atoi(idStr[4:])
	infoTypeName := ""
	switch _typeInt {
	case InfoTypeID:
		infoTypeName = jsonBody.GetPath("inspectConfig", "infoTypes").GetIndex(_indexInt).Get("name").MustString()
		break
	case CustomInfoTypeID:
		infoTypeName = jsonBody.GetPath("inspectConfig", "customInfoTypes").GetIndex(_indexInt).GetPath("infoType", "name").MustString()
		break
	default:
		infoTypeName = "unknown"
		break
	}
	return infoTypeName
}

func InfoTypeList() []string {
	var infoTypes []string
	for k, _ := range InfoTypeMaps {
		infoTypes = append(infoTypes, k)
	}
	return infoTypes
}
