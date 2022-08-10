package consts

import "errors"

const (
	GRuleName     = "DSIEngine"
	GRuleVersion  = "1.0.0"
	GRuleMaxCycle = 1
)

var (
	ErrParameterEmpty = errors.New("parameter is empty")
)

var (
	Red   = string([]byte{27, 91, 51, 49, 109})
	Reset = string([]byte{27, 91, 48, 109})
)

var FileTypes = []string{
	"pdf", "csv", "xls",
	"xlsx", "xlsb", "xlsm",
	"xlt", "xltx", "xltm",
	"ooxml", "ppt", "pptx",
	"ppsx", "pptx", "ppam",
	"potm", "ppsm", "pptm",
	"doc", "docx", "docm",
	"dotx", "dotm", "et",
	"ett", "dps", "dpt",
	"wps", "wpt", "xmind",
	"xps", "c", "cpp",
	"java", "sh", "sql",
	"xml", "bmp", "mp4",
	"tif", "html", "txt",
	"7z", "bz2", "gz",
	"rar", "tar", "zip",
	"ar", "arj", "cpio", "dump",
	"rtf", "7zip", "gzip",
	"ep", "unknown", "epub",
	"key", "pages", "numbers",
}
