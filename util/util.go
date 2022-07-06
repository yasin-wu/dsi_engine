package util

import (
	"math"
	regexp2 "regexp"
	"strings"
)

func RemoveHTML(src string) string {
	re := regexp2.MustCompile(`\\<[\\S\\s]+?\\>`)
	src = re.ReplaceAllStringFunc(src, strings.ToLower)

	re = regexp2.MustCompile(`\\<style[\\S\\s]+?\\</style\\>`)
	src = re.ReplaceAllString(src, "")

	re = regexp2.MustCompile(`\\<script[\\S\\s]+?\\</script\\>`)
	src = re.ReplaceAllString(src, "")

	re = regexp2.MustCompile(`\\<[\\S\\s]+?\\>`)
	src = re.ReplaceAllString(src, "\n")

	re = regexp2.MustCompile(`\\s{2,}`)
	src = re.ReplaceAllString(src, "\n")

	return src
}

func ConvertString2To10(input string) int64 {
	c := getInput(input)
	out := sq(c)
	sum := 0
	for o := range out {
		sum += o
	}
	return int64(sum)
}

func getInput(input string) <-chan int {
	out := make(chan int)
	go func() {
		for _, b := range stringToIntArray(input) {
			out <- b
		}
		close(out)
	}()

	return out
}

func sq(in <-chan int) <-chan int {
	out := make(chan int)

	var base, i float64 = 2, 0
	go func() {
		for n := range in {
			out <- (n - 48) * int(math.Pow(base, i))
			i++
		}
		close(out)
	}()
	return out
}

func stringToIntArray(input string) []int {
	var output []int //nolint:prealloc
	for _, v := range input {
		output = append(output, int(v))
	}
	for i, j := 0, len(output)-1; i < j; i, j = i+1, j-1 {
		output[i], output[j] = output[j], output[i]
	}
	return output
}