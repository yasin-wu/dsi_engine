package parser

import "net/http"

var defaultHeader = http.Header{
	"Accept": []string{"text/plain"},
}

const defaultTika = "http://localhost:9998"

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
