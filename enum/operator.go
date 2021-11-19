//go:generate stringer -type Operator -linecomment
package enum

type Operator int

const (
	AND_OPERATOR Operator = iota //并
	OR_OPERATOR                  //或
)
