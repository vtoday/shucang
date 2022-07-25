package shucang

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/smartwalle/crypto4go"
)

type Client struct {
	isProd    bool
	appId     string
	apiDomain string
	client    *http.Client
	location  *time.Location

	appPrivateKey  *rsa.PrivateKey
	todayPublicKey *rsa.PublicKey
}

type OptionFunc func(c *Client)

func WithTimeLocation(location *time.Location) OptionFunc {
	return func(c *Client) {
		c.location = location
	}
}

func WithHTTPClient(client *http.Client) OptionFunc {
	return func(c *Client) {
		c.client = client
	}
}

func WithApiDomain(apiDomain string) OptionFunc {
	return func(c *Client) {
		c.apiDomain = apiDomain
	}
}

func New(appId, privateKey, publicKey string, isProd bool, opts ...OptionFunc) (client *Client, err error) {
	priKey, err := crypto4go.ParsePKCS8PrivateKey(crypto4go.FormatPKCS8PrivateKey(privateKey))
	if err != nil {
		return nil, err
	}

	pubKey, err := crypto4go.ParsePublicKey(crypto4go.FormatPublicKey(publicKey))
	if err != nil {
		return nil, err
	}

	client = &Client{}
	client.isProd = isProd
	client.appId = appId

	if client.isProd {
		client.apiDomain = kProductionURL
	} else {
		client.apiDomain = kSandboxURL
	}
	client.client = http.DefaultClient
	client.location = time.Local

	client.appPrivateKey = priKey
	client.todayPublicKey = pubKey

	for _, opt := range opts {
		opt(client)
	}

	return client, nil
}

func (c *Client) URLValues(param Param) (value url.Values, err error) {
	var p = url.Values{}
	p.Add("app_id", c.appId)
	p.Add("method", param.APIName())
	p.Add("nonce", nonce())
	p.Add("timestamp", strconv.FormatInt(time.Now().In(c.location).Unix(), 10))

	bytes, err := json.Marshal(param)
	if err != nil {
		return nil, err
	}

	enData, err := encryptWithPKCS1v15(bytes, c.todayPublicKey)
	if err != nil {
		return
	}
	p.Add("data", enData)

	sign, err := signWithPKCS1v15(p, c.appPrivateKey, crypto.SHA256)
	if err != nil {
		return nil, err
	}
	p.Add("sign", sign)
	return p, nil
}

func (c *Client) FormatResponse(code, message, method string, data interface{}) (res *Response, err error) {
	var p = url.Values{}
	p.Add("method", method)
	p.Add("nonce", nonce())
	p.Add("timestamp", strconv.FormatInt(time.Now().In(c.location).Unix(), 10))
	p.Add("code", code)
	p.Add("message", message)

	var enData string
	if data != nil {
		bytes, err := json.Marshal(data)
		if err != nil {
			return nil, err
		}

		enData, err = encryptWithPKCS1v15(bytes, c.todayPublicKey)
		if err != nil {
			return nil, err
		}
	}
	p.Add("data", enData)

	sign, err := signWithPKCS1v15(p, c.appPrivateKey, crypto.SHA256)
	if err != nil {
		return nil, err
	}

	res = &Response{
		Code:      Code(code),
		Message:   p.Get("message"),
		Method:    p.Get("method"),
		Nonce:     p.Get("nonce"),
		Timestamp: p.Get("timestamp"),
		Data:      p.Get("data"),
		Sign:      sign,
	}

	return
}

func (c *Client) ParseRequestParam(req *http.Request, p Param) (err error) {
	request, err := ParseRequest(req)
	if err != nil {
		return
	}

	return c.VerifyRequestParam(request, p)
}

func (c *Client) doRequest(method string, param Param, result interface{}) (err error) {
	var buf io.Reader
	if param != nil {
		p, err := c.URLValues(param)
		if err != nil {
			return err
		}

		s, err := URLValuesToJsonString(p)
		if err != nil {
			return err
		}

		buf = strings.NewReader(s)
	}

	req, err := http.NewRequest(method, c.apiDomain, buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", kContentType)

	resp, err := c.client.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return err
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var res *Response
	if err = json.Unmarshal(data, &res); err != nil {
		return err
	}

	if res.Code != CodeSuccess {
		return res
	}

	if res.Sign != "" {
		if ok, err := c.VerifyResponseSign(res); !ok {
			return err
		}
	}

	if res.Data == "" {
		return
	}

	if result == nil {
		return
	}

	content, err := decryptWithPKCS1v15(res.Data, c.appPrivateKey)
	if err != nil {
		return
	}

	err = json.Unmarshal(content, result)
	if err != nil {
		return
	}

	return
}

func (c *Client) DoRequest(method string, param Param, result interface{}) (err error) {
	return c.doRequest(method, param, result)
}

func (c *Client) VerifyResponseSign(res *Response) (ok bool, err error) {
	var data = url.Values{}
	data.Add("code", string(res.Code))
	data.Add("message", res.Message)
	data.Add("method", res.Method)
	data.Add("nonce", res.Nonce)
	data.Add("timestamp", res.Timestamp)
	data.Add("sign", res.Sign)
	data.Add("data", res.Data)

	return c.VerifySign(data)
}

func (c *Client) VerifyRequestSign(req *Request) (ok bool, err error) {
	var data = url.Values{}
	data.Add("app_id", req.AppId)
	data.Add("method", req.Method)
	data.Add("nonce", req.Nonce)
	data.Add("timestamp", req.Timestamp)
	data.Add("sign", req.Sign)
	data.Add("data", req.Data)

	return c.VerifySign(data)
}

func (c *Client) VerifySign(data url.Values) (ok bool, err error) {
	return verifySign(data, c.todayPublicKey)
}

func (c *Client) VerifyRequestParam(request *Request, p Param) (err error) {
	if ok, err := c.VerifyRequestSign(request); !ok {
		return err
	}

	content, err := decryptWithPKCS1v15(request.Data, c.appPrivateKey)
	if err != nil {
		return
	}

	err = json.Unmarshal(content, p)
	if err != nil {
		return
	}

	return
}

func ParseRequest(req *http.Request) (r *Request, err error) {
	if req.ContentLength == 0 {
		return
	}

	ctype := req.Header.Get(HeaderContentType)
	switch {
	case strings.HasPrefix(ctype, MIMEApplicationJSON):
		err = json.NewDecoder(req.Body).Decode(r)
		if ute, ok := err.(*json.UnmarshalTypeError); ok {
			err = fmt.Errorf("unmarshal type error: expected=%v, got=%v, field=%v, offset=%v", ute.Type, ute.Value, ute.Field, ute.Offset)
		} else if se, ok := err.(*json.SyntaxError); ok {
			err = fmt.Errorf("syntax error: offset=%v, error=%v", se.Offset, se.Error())
			return
		}

	case strings.HasPrefix(ctype, MIMEApplicationForm), strings.HasPrefix(ctype, MIMEMultipartForm):
		if strings.HasPrefix(ctype, MIMEApplicationForm) {
			err = req.ParseForm()
		} else if strings.HasPrefix(ctype, MIMEMultipartForm) {
			err = req.ParseMultipartForm(defaultMemory)
		}
		if err != nil {
			return
		}

		r.AppId = req.FormValue("app_id")
		r.Method = req.FormValue("method")
		r.Nonce = req.FormValue("nonce")
		r.Timestamp = req.FormValue("timestamp")
		r.Sign = req.FormValue("sign")
		r.Data = req.FormValue("data")

	default:
		err = fmt.Errorf("content-type: %s is unsupported", ctype)
		return
	}
	return
}

func verifySign(data url.Values, key *rsa.PublicKey) (ok bool, err error) {
	sign := data.Get(kSignNodeName)

	s := toBeSignedString(data)
	return verifyData([]byte(s), sign, key)
}

func encryptWithPKCS1v15(msg []byte, publicKey *rsa.PublicKey) (s string, err error) {
	ens, err := crypto4go.RSAEncryptWithKey(msg, publicKey)
	if err != nil {
		return
	}
	s = base64.StdEncoding.EncodeToString(ens)
	return
}

func decryptWithPKCS1v15(s string, privateKey *rsa.PrivateKey) (b []byte, err error) {
	msg, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return
	}
	return crypto4go.RSADecryptWithKey(msg, privateKey)
}

func signWithPKCS1v15(param url.Values, privateKey *rsa.PrivateKey, hash crypto.Hash) (s string, err error) {
	var src = toBeSignedString(param)
	sig, err := crypto4go.RSASignWithKey([]byte(src), privateKey, hash)
	if err != nil {
		return "", err
	}
	s = base64.StdEncoding.EncodeToString(sig)
	return s, nil
}

func toBeSignedString(param url.Values) string {
	if param == nil {
		param = make(url.Values, 0)
	}

	var pList = make([]string, 0, 0)
	for key := range param {
		if key == kSignNodeName {
			continue
		}
		var value = strings.TrimSpace(param.Get(key))
		if len(value) > 0 {
			pList = append(pList, key+"="+value)
		}
	}
	sort.Strings(pList)
	return strings.Join(pList, "&")
}

func URLValuesToJsonString(param url.Values) (s string, err error) {
	if param == nil {
		param = make(url.Values, 0)
	}

	m := make(map[string]string)
	for key := range param {
		var value = strings.TrimSpace(param.Get(key))
		m[key] = value
	}

	js, err := json.Marshal(m)
	if err != nil {
		return
	}
	s = string(js)

	return
}

func verifyData(data []byte, sign string, key *rsa.PublicKey) (ok bool, err error) {
	signBytes, err := base64.StdEncoding.DecodeString(sign)
	if err != nil {
		return false, err
	}

	if err = crypto4go.RSAVerifyWithKey(data, signBytes, key, crypto.SHA256); err != nil {
		return false, err
	}
	return true, nil
}

func nonce() string {
	id := uuid.New().String()
	r := sha1.Sum([]byte(id))
	return hex.EncodeToString(r[:])
}
