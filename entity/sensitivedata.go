package entity

/**
 * @author: yasinWu
 * @date: 2022/1/13 13:45
 * @description: 敏感数据
 */
type SensitiveData struct {
	ID       string    `json:"id"`        // 敏感数据id
	FileName string    `json:"file_name"` // 文件名字
	FileType string    `json:"file_type"` // 文件类型
	FilePath string    `json:"file_path"` // 文件路径
	FileSize int64     `json:"file_size"` // 文件大小,单位byte
	Content  string    `json:"content"`   // 文件内容
	Policies []*Policy `json:"policies"`  // 策略组
}
