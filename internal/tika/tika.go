package tika

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"reflect"
	"strings"

	"golang.org/x/net/context/ctxhttp"
)

type Client struct {
	url        string
	httpClient *http.Client
}

func NewClient(httpClient *http.Client, urlString string) *Client {
	return &Client{httpClient: httpClient, url: urlString}
}

type Parser struct {
	Name           string
	Decorated      bool
	Composite      bool
	Children       []Parser
	SupportedTypes []string
}

type MIMEType struct {
	Alias     []string
	SuperType string
}

type Detector struct {
	Name      string
	Composite bool
	Children  []Detector
}

type Translator string

const (
	Lingo24Translator   Translator = "org.apache.tika.language.translate.Lingo24Translator"
	GoogleTranslator    Translator = "org.apache.tika.language.translate.GoogleTranslator"
	MosesTranslator     Translator = "org.apache.tika.language.translate.MosesTranslator"
	JoshuaTranslator    Translator = "org.apache.tika.language.translate.JoshuaTranslator"
	MicrosoftTranslator Translator = "org.apache.tika.language.translate.MicrosoftTranslator"
	YandexTranslator    Translator = "org.apache.tika.language.translate.YandexTranslator"
)

const XTIKAContent = "X-TIKA:content"

func (c *Client) call(ctx context.Context, input io.Reader, method, path string, header http.Header) ([]byte, error) {
	if c.httpClient == nil {
		c.httpClient = http.DefaultClient
	}

	req, err := http.NewRequest(method, c.url+path, input)
	if err != nil {
		return nil, err
	}
	req.Header = header

	resp, err := ctxhttp.Do(ctx, c.httpClient, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("response code %v", resp.StatusCode)
	}
	return ioutil.ReadAll(resp.Body)
}

func (c *Client) callString(ctx context.Context, input io.Reader, method, path string, header http.Header) (string, error) {
	body, err := c.call(ctx, input, method, path, header)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func (c *Client) Parse(ctx context.Context, input io.Reader, header http.Header) (string, error) {
	return c.callString(ctx, input, "PUT", "/tika", header)
}

func (c *Client) ParseRecursive(ctx context.Context, input io.Reader) ([]string, error) {
	m, err := c.MetaRecursive(ctx, input)
	if err != nil {
		return nil, err
	}
	var r []string
	for _, d := range m {
		if content := d[XTIKAContent]; len(content) > 0 {
			r = append(r, content[0])
		}
	}
	return r, nil
}

func (c *Client) Meta(ctx context.Context, input io.Reader, header http.Header) (string, error) {
	return c.callString(ctx, input, "PUT", "/meta", header)
}

func (c *Client) MetaField(ctx context.Context, input io.Reader, field string, header http.Header) (string, error) {
	return c.callString(ctx, input, "PUT", fmt.Sprintf("/meta/%v", field), header)
}

func (c *Client) Detect(ctx context.Context, input io.Reader, header http.Header) (string, error) {
	return c.callString(ctx, input, "PUT", "/detect/stream", header)
}

func (c *Client) Language(ctx context.Context, input io.Reader, header http.Header) (string, error) {
	return c.callString(ctx, input, "PUT", "/language/stream", header)
}

func (c *Client) LanguageString(ctx context.Context, input string, header http.Header) (string, error) {
	r := strings.NewReader(input)
	return c.callString(ctx, r, "PUT", "/language/string", header)
}

func (c *Client) MetaRecursive(ctx context.Context, input io.Reader) ([]map[string][]string, error) {
	return c.MetaRecursiveType(ctx, input, "text")
}

func (c *Client) MetaRecursiveType(ctx context.Context, input io.Reader, contentType string) ([]map[string][]string, error) {
	path := "/rmeta"
	if contentType != "" {
		path = fmt.Sprintf("/rmeta/%s", contentType)
	}
	body, err := c.call(ctx, input, "PUT", path, nil)
	if err != nil {
		return nil, err
	}
	var m []map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, err
	}
	var r []map[string][]string //nolint:prealloc
	for _, d := range m {
		doc := make(map[string][]string)
		r = append(r, doc)
		for k, v := range d {
			switch vt := v.(type) {
			case string:
				doc[k] = []string{vt}
			case []any:
				for _, i := range vt {
					s, ok := i.(string)
					if !ok {
						return nil, fmt.Errorf("field %q has value %v and type %T, expected a string or []string", k, v, vt)
					}
					doc[k] = append(doc[k], s)
				}
			default:
				return nil, fmt.Errorf("field %q has value %v and type %v, expected a string or []string", k, v, reflect.TypeOf(v))
			}
		}
	}
	return r, nil
}

func (c *Client) Translate(ctx context.Context, input io.Reader, t Translator, src, dst string, header http.Header) (string, error) {
	return c.callString(ctx, input, "POST", fmt.Sprintf("/translate/all/%s/%s/%s", t, src, dst), header)
}

func (c *Client) Version(ctx context.Context) (string, error) {
	return c.callString(ctx, nil, "GET", "/version", nil)
}

var jsonHeader = http.Header{"Accept": []string{"application/json"}}

func (c *Client) callUnmarshal(ctx context.Context, path string, v any) error {
	body, err := c.call(ctx, nil, "GET", path, jsonHeader)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, v)
}

func (c *Client) Parsers(ctx context.Context) (*Parser, error) {
	p := new(Parser)
	if err := c.callUnmarshal(ctx, "/parsers/details", p); err != nil {
		return nil, err
	}
	return p, nil
}

func (c *Client) MIMETypes(ctx context.Context) (map[string]MIMEType, error) {
	mt := make(map[string]MIMEType)
	if err := c.callUnmarshal(ctx, "/mime-types", &mt); err != nil {
		return nil, err
	}
	return mt, nil
}

func (c *Client) Detectors(ctx context.Context) (*Detector, error) {
	d := new(Detector)
	if err := c.callUnmarshal(ctx, "/detectors", d); err != nil {
		return nil, err
	}
	return d, nil
}
