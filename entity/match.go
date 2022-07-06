package entity

/**
 * @author: yasinWu
 * @date: 2022/1/13 13:48
 * @description: 命中信息
 */
type Match struct {
	Id        uint        // 命中信息id
	From      uint64      // 命中开始位置
	To        uint64      // 名字结束位置
	Flags     uint        // flags
	Context   interface{} // 命中内容
	InputData string      // 输入内容
	Distance  int         // 汉明距离
}
