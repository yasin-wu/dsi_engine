package entity

/**
 * @author: yasinWu
 * @date: 2022/1/13 14:40
 * @description: 文件信息
 */
type FileInfo struct {
	Name     string // 文件名字
	Path     string // 文件路径
	FileType string // 文件类型
	Size     int64  // 文件大小,单位byte
	Content  string // 文件内容
}
