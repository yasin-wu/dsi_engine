//go:generate stringer -type Operator -linecomment
package enum

type Operator int

const (
	AndOperator Operator = iota // 并
	OrOperator                  // 或
)
