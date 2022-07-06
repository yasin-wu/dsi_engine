package entity

import (
	js "github.com/bitly/go-simplejson"
	"github.com/yasin-wu/dsi_engine/v2/enum"
)

/**
 * @author: yasinWu
 * @date: 2022/1/13 13:46
 * @description: 策略信息
 */
type Policy struct {
	Id        string          `json:"id"`        // 策略id
	Operators []enum.Operator `json:"operators"` // 规则之间关系
	Rules     []Rule          `json:"rules"`     // 规则组
}

/**
 * @author: yasinWu
 * @date: 2022/1/13 13:47
 * @description: 规则信息
 */
type Rule struct {
	Id               string        `json:"id"`                // 规则id
	Name             string        `json:"name"`              // 规则名字
	Type             enum.RuleType `json:"type"`              // 规则类型
	Level            int           `json:"level"`             // 规则等级
	ForWardThreshold int           `json:"forward_threshold"` // 默认匹配次数
	ReverseThreshold int           `json:"reverse_threshold"` // 反向关键字匹配次数
	ForWardKeyList   []string      `json:"forward_key_list"`  // 正向关键字,模糊关键字
	ReverseKeyList   []string      `json:"reverse_key_list"`  // 反向关键字
	Regexp           string        `json:"regexp"`            // 正则和数据标识符
	CharacterSpace   int           `json:"character_space"`   // 字符间距<=5
	FingerRatio      int           `json:"finger_ratio"`      // 指纹相似度
	FingerPrints     *js.Json      `json:"finger_prints"`     // 指纹
}
