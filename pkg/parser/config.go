package parser

import "net/http"

var defaultHeader = http.Header{
	"Accept": []string{"text/plain"},
}

const defaultTika = "http://localhost:9998"

/**
 * @author: yasinWu
 * @date: 2022/1/13 14:42
 * @params: header http.Header
 * @return: Option
 * @description: 配置http header
 */
func WithHeader(header http.Header) Option {
	return func(parser *Parser) {
		parser.header = header
	}
}

/**
 * @author: yasinWu
 * @date: 2022/1/13 14:42
 * @params: client *http.Client
 * @return: Option
 * @description: 配置http client
 */
func WithClient(client *http.Client) Option {
	return func(parser *Parser) {
		parser.client = client
	}
}
