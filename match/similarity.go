package match

import (
	"fmt"
	"hash/fnv"
	"strconv"
	"strings"

	"github.com/yasin-wu/dsi_engine/v2/util"

	"github.com/yanyiwu/gojieba"
)

type wordWeight struct {
	Word   string
	Weight float64
	Print  int64
}

func (f *fingerPrint) extractWithWeight(input string, topKey int, addWords []string) ([]wordWeight, []string) {
	if topKey == 0 {
		_, num := f.getAllWords(input, false, addWords)
		topKeyStr := strconv.FormatFloat(float64(num)*f.wordRatio, 'f', 0, 64)
		topKey, _ = strconv.Atoi(topKeyStr)
	}
	var err error
	g := gojieba.NewJieba()
	for _, addWord := range addWords {
		g.AddWord(addWord)
	}
	defer g.Free()
	input = util.RemoveHtml(input)
	wordWeights := g.ExtractWithWeight(input, topKey)
	binaryWeights := make([]float64, 32)
	wordWeightList := make([]wordWeight, 0)
	for _, ww := range wordWeights {
		var w wordWeight
		bitHash := f.strHashBitCode(ww.Word)
		weights := f.calcWithWeight(bitHash, ww.Weight)
		binaryWeights, err = f.sliceInnerPlus(binaryWeights, weights)
		if err != nil {
			return nil, nil
		}
		w.Word = ww.Word
		w.Weight = ww.Weight
		w.Print = util.ConvertString2To10(bitHash)

		wordWeightList = append(wordWeightList, w)
	}
	fingerPrint := make([]string, 0)
	for _, b := range binaryWeights {
		if b > 0 {
			fingerPrint = append(fingerPrint, "1")
		} else {
			fingerPrint = append(fingerPrint, "0")
		}
	}
	return wordWeightList, fingerPrint
}

func (f *fingerPrint) hammingDistance(arr1, arr2 []string) int {
	count := 0
	for i, v1 := range arr1 {
		if v1 != arr2[i] {
			count++
		}
	}
	return count
}

func (f *fingerPrint) getAllWords(input string, hmm bool, addWords []string) ([]string, int) {
	g := gojieba.NewJieba()
	for _, addWord := range addWords {
		g.AddWord(addWord)
	}
	defer g.Free()
	words := g.Cut(input, hmm)
	return words, len(words)
}

func (f *fingerPrint) strHashBitCode(str string) string {
	h := fnv.New32a()
	h.Write([]byte(str))
	b := int64(h.Sum32())
	return fmt.Sprintf("%032b", b)
}

func (f *fingerPrint) calcWithWeight(bitHash string, weight float64) []float64 {
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

func (f *fingerPrint) sliceInnerPlus(arr1, arr2 []float64) (dstArr []float64, err error) {
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
