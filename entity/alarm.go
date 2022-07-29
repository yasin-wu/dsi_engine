package entity

import (
	"time"

	"github.com/yasin-wu/dsi_engine/v2/enum"
)

/**
 * @author: yasinWu
 * @date: 2022/1/13 13:42
 * @description: 告警信息
 */
type Alarm struct {
	ID          string      `json:"id"`           //  告警信息id
	FileName    string      `json:"file_name"`    // 文件名
	FilePath    string      `json:"file_path"`    // 文件路径
	FileType    string      `json:"file_type"`    // 文件类型
	FileSize    int64       `json:"file_size"`    // 文件大小,单位byte
	MatchNote   string      `json:"match_note"`   // 命中笔记
	MatchTimes  int         `json:"match_times"`  // 命中次数
	PolicyID    string      `json:"policy_id"`    // 策略id
	AttachWords string      `json:"attach_words"` // 命中单词
	RuleSnaps   []*RuleSnap `json:"rule_snaps"`   // 命中规则快照
	SnapShot    string      `json:"snap_shot"`    // 文件内容快照
	FingerRatio int         `json:"finger_ratio"` // 指纹相似度
	CreatedAt   time.Time   `json:"created_at"`   // 告警事件
}

/**
 * @author: yasinWu
 * @date: 2022/1/13 13:42
 * @description: 命中规则快照
 */
type RuleSnap struct {
	ID         string        `json:"id"`          // 规则id
	Name       string        `json:"name"`        // 规则名字
	Type       enum.RuleType `json:"type"`        // 规则类型
	MatchTimes int           `json:"match_times"` // 命中次数
	Level      int           `json:"level"`       // 规则等级
	Snap       string        `json:"snap"`        // 名字快照
}
