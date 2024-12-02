package match

import (
	"fmt"
	"strings"

	"github.com/yasin-wu/dsi_engine/v2/internal/util"

	"github.com/yasin-wu/dsi_engine/v2/pkg/entity"
)

type fingerPrint struct {
	wordRatio float64
}

var _ Engine = (*fingerPrint)(nil)

func (f *fingerPrint) Match(rule entity.Rule, sensitiveData entity.SensitiveData) ([]*entity.Match, string, bool) {
	inputData := sensitiveData.FileName
	distance, matched := f.do(rule.FingerPrints, rule.FingerRatio, sensitiveData.FileName)
	if !matched {
		inputData = sensitiveData.Content
		distance, matched = f.do(rule.FingerPrints, rule.FingerRatio, sensitiveData.Content)
	}
	return []*entity.Match{{Distance: distance}}, inputData, matched
}

func (f *fingerPrint) do(fingerPrints entity.FingerPrints, fingerRatio int, inputData string) (int, bool) {
	_, dstFinger := f.extractWithWeight(inputData, 0, nil)
	distance := f.computeFileHammingDistance(fingerPrints, dstFinger)
	distance2 := f.computeWordHammingDistance(fingerPrints, dstFinger)
	if distance2 < distance {
		distance = distance2
	}
	if distance <= fingerRatio {
		return distance, true
	}
	return distance, false
}

func (f *fingerPrint) computeFileHammingDistance(fingerPrints entity.FingerPrints, dstFinger []string) int {
	distance := 100
	fileList, ok := fingerPrints["filelist"]
	if !ok {
		return distance
	}
	var fileListMap []map[string]any
	if err := util.Unmarshal(fileList, &fileListMap); err != nil {
		return distance
	}
	for _, file := range fileListMap {
		if file == nil {
			break
		}
		pt, _ := file["print"].(int64)
		srcFinger := strings.Split(fmt.Sprintf("%032b", pt), "")
		diff := f.hammingDistance(srcFinger, dstFinger)
		if diff < distance {
			distance = diff
		}
	}
	return distance
}
func (f *fingerPrint) computeWordHammingDistance(fingerPrints entity.FingerPrints, dstFinger []string) int {
	var err error
	distance := 100
	keyList, ok := fingerPrints["keylist"]
	if !ok {
		return distance
	}
	var keyListMap []map[string]any
	if err := util.Unmarshal(keyList, &keyListMap); err != nil {
		return distance
	}
	binaryWeights := make([]float64, 32)
	for _, key := range keyListMap {
		if key == nil {
			break
		}
		name, _ := key["name"].(string)
		weight, _ := key["weight"].(float64)
		bitHash := f.strHashBitCode(name)
		weights := f.calcWithWeight(bitHash, weight)
		binaryWeights, err = f.sliceInnerPlus(binaryWeights, weights)
		if err != nil {
			return distance
		}
	}
	fingerPrint := make([]string, 0)
	for _, b := range binaryWeights {
		if b > 0 {
			fingerPrint = append(fingerPrint, "1")
		} else {
			fingerPrint = append(fingerPrint, "0")
		}
	}
	distance = f.hammingDistance(fingerPrint, dstFinger)
	return distance
}
