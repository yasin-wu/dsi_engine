package policy

import (
	js "github.com/bitly/go-simplejson"
	"github.com/yasin-wu/dsi_engine/v2/enum"
)

type SensitiveData struct {
	Id       string    `json:"id"`
	FileName string    `json:"file_name"`
	FileType string    `json:"file_type"`
	FilePath string    `json:"file_path"`
	FileSize int64     `json:"file_size"`
	Content  string    `json:"content"`
	Policies []*Policy `json:"policies"`
}

type Policy struct {
	Id        string          `json:"id"`
	Operators []enum.Operator `json:"operators"`
	Rules     []*Rule         `json:"rules"`
}

type Rule struct {
	Id               string        `json:"id"`
	Name             string        `json:"name"`
	Type             enum.RuleType `json:"type"`
	Level            int           `json:"level"`
	ForWardThreshold int           `json:"forward_threshold"` //默认匹配次数
	ReverseThreshold int           `json:"reverse_threshold"` //反向关键字匹配次数
	ForWardKeyList   []string      `json:"forward_key_list"`  //正向关键字,模糊关键字
	ReverseKeyList   []string      `json:"reverse_key_list"`  //反向关键字
	Regexp           string        `json:"regexp"`            //正则和数据标识符
	CharacterSpace   int           `json:"character_space"`   //字符间距<=5
	FingerRatio      int           `json:"finger_ratio"`      //指纹相似度
	FingerPrints     *js.Json      `json:"finger_prints"`     //指纹
}
