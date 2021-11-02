package policy

import "time"

type Alarm struct {
	Id          string      `json:"id"`
	FileName    string      `json:"file_name"`
	FilePath    string      `json:"file_path"`
	FileType    string      `json:"file_type"`
	FileSize    int64       `json:"file_size"`
	MatchNote   string      `json:"match_note"`
	MatchTimes  int         `json:"match_times"`
	PolicyId    string      `json:"policy_id"`
	AttachWords string      `json:"attach_words"`
	RuleSnaps   []*RuleSnap `json:"rule_snaps"`
	SnapShot    string      `json:"snap_shot"`
	FingerRatio int         `json:"finger_ratio"`
	CreatedAt   time.Time   `json:"created_at"`
}

type RuleSnap struct {
	Id         string `json:"id"`
	Name       string `json:"name"`
	Type       int    `json:"type"`
	MatchTimes int    `json:"match_times"`
	Level      int    `json:"level"`
	Snap       string `json:"snap"`
}
