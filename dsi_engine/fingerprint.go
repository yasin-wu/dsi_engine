package dsi_engine

import (
	"fmt"
	"hash/fnv"
	"strings"

	"github.com/yasin-wu/dsi_engine/policy"

	"github.com/yasin-wu/dsi_engine/regexp_engine"

	js "github.com/bitly/go-simplejson"
	"github.com/yasin-wu/utils/similarity"
)

type FingerPrint struct {
	dsiEngine *DsiEngine
}

var _ MatchEngine = (*FingerPrint)(nil)

func (this *FingerPrint) match(rule *policy.Rule) ([]*regexp_engine.Match, string, bool) {
	inputData := this.dsiEngine.sensitiveData.FileName
	distance, matched := this.do(rule.FingerPrints,
		rule.FingerRatio, this.dsiEngine.sensitiveData.FileName)
	if !matched {
		inputData = this.dsiEngine.sensitiveData.Content
		distance, matched = this.do(rule.FingerPrints,
			rule.FingerRatio, this.dsiEngine.sensitiveData.Content)
	}
	return []*regexp_engine.Match{{Distance: distance}}, inputData, matched
}

func (this *FingerPrint) do(fingerPrints *js.Json, fingerRatio int, inputData string) (int, bool) {
	_, dstFinger := similarity.ExtractWithWeight(inputData, 0, nil)
	distance := this.computeFileHammingDistance(fingerPrints, dstFinger)
	distance2 := this.computeWordHammingDistance(fingerPrints, dstFinger)
	if distance2 < distance {
		distance = distance2
	}
	if distance <= fingerRatio {
		return distance, true
	}
	return distance, false
}

func (this *FingerPrint) computeFileHammingDistance(fingerPrints *js.Json, dstFinger []string) int {
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
		diff := similarity.HammingDistance(srcFinger, dstFinger)
		if diff < distance {
			distance = diff
		}
	}
	return distance
}
func (this *FingerPrint) computeWordHammingDistance(fingerPrints *js.Json, dstFinger []string) int {
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
		bitHash := this.strHashBitCode(key.Get("name").MustString())
		weights := this.calcWithWeight(bitHash, key.Get("weight").MustFloat64())
		binaryWeights, err = this.sliceInnerPlus(binaryWeights, weights)
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
	distance = similarity.HammingDistance(fingerPrint, dstFinger)
	return distance
}

func (this *FingerPrint) strHashBitCode(str string) string {
	h := fnv.New32a()
	h.Write([]byte(str))
	b := int64(h.Sum32())
	return fmt.Sprintf("%032b", b)
}

func (this *FingerPrint) calcWithWeight(bitHash string, weight float64) []float64 {
	bitHashes := strings.Split(bitHash, "")
	binaries := make([]float64, 0)

	for _, bit := range bitHashes {
		if bit == "0" {
			binaries = append(binaries, float64(-1)*weight)
		} else {
			binaries = append(binaries, weight)
		}
	}
	return binaries
}

func (this *FingerPrint) sliceInnerPlus(arr1, arr2 []float64) (dstArr []float64, err error) {
	dstArr = make([]float64, len(arr1), len(arr1))

	if arr1 == nil || arr2 == nil {
		err = fmt.Errorf("sliceInnerPlus array nil")
		return
	}
	if len(arr1) != len(arr2) {
		err = fmt.Errorf("sliceInnerPlus array Length NOT match, %v != %v", len(arr1), len(arr2))
		return
	}

	for i, v1 := range arr1 {
		dstArr[i] = v1 + arr2[i]
	}

	return
}