package models

import "time"

type PolicyAlarm struct {
	Id          string      `json:"id"`
	FileName    string      `json:"file_name"`
	FilePath    string      `json:"file_path"`
	FileSize    int64       `json:"file_size"`
	MatchNote   string      `json:"match_note"`
	MatchTimes  int         `json:"match_times"`
	PolicyId    string      `json:"policy_id"`
	AttachWords string      `json:"attach_words"`
	RuleSnaps   []*RuleSnap `json:"rule_snaps"`
	SnapShot    string      `json:"snap_shot"`
	CreatedAt   time.Time   `json:"created_at"`
}

type RuleSnap struct {
	RuleId     string `json:"Rule_id"`
	RuleName   string `json:"rule_name"`
	RuleType   int    `json:"rule_type"`
	MatchTimes int    `json:"match_times"`
	Level      int    `json:"level"`
	LevelName  string `json:"level_name"`
	Snap       string `json:"snap"`
}
