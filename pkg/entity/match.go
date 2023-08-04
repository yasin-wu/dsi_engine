package entity

/**
 * @author: yasinWu
 * @date: 2022/1/13 13:48
 * @description: 命中信息
 */
type Match struct {
	ID        int    // 命中信息id
	From      int    // 命中开始位置
	To        int    // 命中结束位置
	Context   any    // 命中内容
	InputData string // 输入内容
	Distance  int    // 汉明距离
}

/**
 * @author: yasinWu
 * @date: 2022/1/13 13:49
 * @description: 正则信息
 */
type Regexp struct {
	ID     int    // 正则id
	Regexp string // 正则表达式
}
