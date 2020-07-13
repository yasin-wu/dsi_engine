package models

type FilePolicy struct {
	Id          string        `json:"id"`
	FileName    string        `json:"file_name"`
	FilePath    string        `json:"file_path"`
	FileSize    int           `json:"file_size"`
	Content     string        `json:"content"`
	PolicyInfos []*PolicyInfo `json:"policy_infos"`
}

type PolicyInfo struct {
	PolicyId     string         `json:"policy_id"`
	Operators    []int          `json:"operators"`
	RuleContents []*RuleContent `json:"rule_contents"`
}

type RuleContent struct {
	RuleId           string   `json:"rule_id"`
	RuleName         string   `json:"rule_name"`
	Type             int      `json:"type"`
	TypeName         string   `json:"type_name"`
	Level            int      `json:"level"`
	LevelName        int      `json:"level_name"`
	ForWardThreshold int      `json:"forward_threshold"` //默认匹配次数
	ReverseThreshold int      `json:"reverse_threshold"` //反向关键字匹配次数
	ForWardKeyList   []string `json:"forward_key_list"`  //正向关键字
	ReverseKeyList   []string `json:"reverse_key_list"`  //反向关键字
	Regexp           string   `json:"regexp"`            //正则和数据标识符
	BaseRegexp       string   `json:"base_regexp"`       //模糊关键字
	CharacterSpace   string   `json:"character_space"`   //字符间距<=5
}
