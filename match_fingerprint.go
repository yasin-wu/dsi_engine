package dlp

import (
	"fmt"
	js "github.com/bitly/go-simplejson"
	"github.com/yasin-wu/similarity"
	"hash/fnv"
	"strings"
)

/**
 * @author: yasin
 * @date: 2020/7/23 08:53
 * @description：RuleTypeFingerDNA
 */
func (this *GRule) MatchFinger() (int, string, bool) {
	inputData := this.FilePolicy.FileName
	distance, matched := matchFinger(this.FilePolicy.FingerPrints, this.FilePolicy.FingerRatio, this.FilePolicy.FileName)
	if !matched {
		inputData = this.FilePolicy.Content
		distance, matched = matchFinger(this.FilePolicy.FingerPrints, this.FilePolicy.FingerRatio, this.FilePolicy.Content)
	}
	return distance, inputData, matched
}

func matchFinger(fingerPrints *js.Json, fingerRatio int, inputData string) (int, bool) {
	_, dstFinger := similarity.ExtractWithWeight(inputData, 0, nil)
	distance := computeFileHammingDistance(fingerPrints, dstFinger)
	distance2 := computeWordHammingDistance(fingerPrints, dstFinger)
	if distance2 < distance {
		distance = distance2
	}

	if distance <= fingerRatio {
		return distance, true
	}
	return distance, false
}

func computeFileHammingDistance(fingerPrints *js.Json, dstFinger []string) int {
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
func computeWordHammingDistance(fingerPrints *js.Json, dstFinger []string) int {
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
		bitHash := strHashBitCode(key.Get("name").MustString())
		weights := calcWithWeight(bitHash, key.Get("weight").MustFloat64())
		binaryWeights, err = sliceInnerPlus(binaryWeights, weights)
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

func strHashBitCode(str string) string {
	h := fnv.New32a()
	h.Write([]byte(str))
	b := int64(h.Sum32())
	return fmt.Sprintf("%032b", b)
}

func calcWithWeight(bitHash string, weight float64) []float64 {
	bitHashs := strings.Split(bitHash, "")
	binarys := make([]float64, 0)

	for _, bit := range bitHashs {
		if bit == "0" {
			binarys = append(binarys, float64(-1)*weight)
		} else {
			binarys = append(binarys, float64(weight))
		}
	}

	return binarys
}

func sliceInnerPlus(arr1, arr2 []float64) (dstArr []float64, err error) {
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
