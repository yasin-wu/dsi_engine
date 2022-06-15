package match

import (
	"fmt"
	"strings"

	js "github.com/bitly/go-simplejson"
	"github.com/yasin-wu/dsi_engine/v2/entity"
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

func (f *fingerPrint) do(fingerPrints *js.Json, fingerRatio int, inputData string) (int, bool) {
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

func (f *fingerPrint) computeFileHammingDistance(fingerPrints *js.Json, dstFinger []string) int {
	distance := 100
	fileList, ok := fingerPrints.CheckGet("filelist")
	if !ok {
		return distance
	}
	for i := 0; ; i++ {
		file := fileList.GetIndex(i)
		if file.Interface() == nil {
			break
		}
		srcFinger := strings.Split(fmt.Sprintf("%032b", file.Get("print").MustInt64()), "")
		diff := f.hammingDistance(srcFinger, dstFinger)
		if diff < distance {
			distance = diff
		}
	}
	return distance
}
func (f *fingerPrint) computeWordHammingDistance(fingerPrints *js.Json, dstFinger []string) int {
	var err error
	distance := 100
	keyList, ok := fingerPrints.CheckGet("keylist")
	if !ok {
		return distance
	}
	binaryWeights := make([]float64, 32)
	for i := 0; ; i++ {
		key := keyList.GetIndex(i)
		if key.Interface() == nil {
			break
		}
		bitHash := f.strHashBitCode(key.Get("name").MustString())
		weights := f.calcWithWeight(bitHash, key.Get("weight").MustFloat64())
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
