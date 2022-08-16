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
	"github.com/sirupsen/logrus"
	"github.com/smartwalle/crypto4go"
)

type Client struct {
	isProd    bool
	appId     string
	apiDomain string
	client    *http.Client
	location  *time.Location
	logger    *logrus.Entry

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

func WithLogger(entry *logrus.Entry) OptionFunc {
	return func(c *Client) {
		c.logger = entry
	}
}

func New(appId, privateKey, publicKey string, isProd bool, opts ...OptionFunc) (client *Client, e *BizErr) {
	priKey, err := crypto4go.ParsePKCS8PrivateKey(crypto4go.FormatPKCS8PrivateKey(privateKey))
	if err != nil {
		return nil, NewError(CCertError, "私钥配置错误").SetErr(err)
	}

	pubKey, err := crypto4go.ParsePublicKey(crypto4go.FormatPublicKey(publicKey))
	if err != nil {
		return nil, NewError(CCertError, "公钥配置错误").SetErr(err)
	}

	client = &Client{}
	client.isProd = isProd
	client.appId = appId
	client.logger = logrus.NewEntry(logrus.StandardLogger())

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

	client.logger.Infof("Client init, app_id: %s private: %s, public: %s api_domain: %s", appId, privateKey, publicKey, client.apiDomain)

	return client, nil
}

func (c *Client) URLValues(param Param) (value url.Values, e *BizErr) {
	var p = url.Values{}
	p.Add("app_id", c.appId)
	p.Add("method", param.APIName())
	p.Add("nonce", Nonce())
	p.Add("timestamp", strconv.FormatInt(time.Now().In(c.location).Unix(), 10))

	bytes, err := json.Marshal(param)
	if err != nil {
		return nil, NewError(CUnknown, "Data to json 失败").SetErr(err)
	}

	enData, err := encryptWithPKCS1v15(bytes, c.todayPublicKey)
	if err != nil {
		return nil, NewError(CUnknown, "数据加密失败").SetErr(err)
	}
	p.Add("data", enData)

	sign, src, err := signWithPKCS1v15(p, c.appPrivateKey, crypto.SHA256)
	if err != nil {
		c.logger.Infof("URLValues sign string: %s", src)
		return nil, NewError(CUnknown, "数据签名失败").SetErr(err)
	}
	p.Add("sign", sign)
	return p, nil
}

func (c *Client) FormatResponse(code, message, method string, data interface{}) (res *Response, e *BizErr) {
	var p = url.Values{}
	p.Add("method", method)
	p.Add("nonce", Nonce())
	p.Add("timestamp", strconv.FormatInt(time.Now().In(c.location).Unix(), 10))
	p.Add("code", code)
	p.Add("message", message)

	var enData string
	if data != nil {
		bytes, err := json.Marshal(data)
		if err != nil {
			return nil, NewError(CUnknown).SetErr(err)
		}

		enData, err = encryptWithPKCS1v15(bytes, c.todayPublicKey)
		if err != nil {
			return nil, NewError(CUnknown, "数据加密失败").SetErr(err)
		}
	}
	p.Add("data", enData)

	sign, src, err := signWithPKCS1v15(p, c.appPrivateKey, crypto.SHA256)
	if err != nil {
		c.logger.Infof("FormatResponse sign string: %s", src)
		return nil, NewError(CUnknown, "数据签名失败").SetErr(err)
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

func (c *Client) ParseRequestParam(req *http.Request, p Param) (e *BizErr) {
	request, err := ParseRequest(req)
	if err != nil {
		return NewError(CDataDecodeFailure).SetErr(err)
	}

	if err = c.CheckRequestParams(request); err != nil {
		return
	}

	return c.VerifyRequestParam(request, p)
}

func (c *Client) CheckRequestParams(request *Request) *BizErr {
	if request == nil {
		return NewError(CParamInvalid)
	}
	if request.AppId == "" {
		return NewError(CNotAppIdParam)
	}
	if request.Nonce == "" {
		return NewError(CNotNonceParam)
	}
	if request.Data == "" {
		return NewError(CNotDataParam)
	}

	return nil
}

func (c *Client) doRequest(method string, param Param, result interface{}) (e *BizErr) {
	var buf io.Reader
	var reqBody string
	var err error
	if param != nil {
		p, e := c.URLValues(param)
		if e != nil {
			return e
		}

		reqBody, err = URLValuesToJsonString(p)
		if err != nil {
			return NewError(CUnknown).SetErr(err)
		}

		buf = strings.NewReader(reqBody)
	}

	req, err := http.NewRequest(method, c.apiDomain, buf)
	if err != nil {
		return NewError(CUnknown).SetErr(err)
	}
	req.Header.Set("Content-Type", kContentType)

	resp, err := c.client.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return NewError(CApiRequestFailure).SetErr(err)
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return NewError(CUnknown).SetErr(err)
	}

	c.logger.Infof("Shucang api request, url: %s, request: %s, response: %s", c.apiDomain, reqBody, string(data))

	var res *Response
	if err = json.Unmarshal(data, &res); err != nil {
		return NewError(CDataDecodeFailure).SetErr(err)
	}

	if res.Code == "" {
		return NewError(CApiResponseFailure)
	}

	if res.Code != CSuccess {
		return NewError(CApiResBizError).SetErr(NewError(res.Code, res.Message))
	}

	if res.Sign == "" {
		return NewError(CNotSignParam)
	}

	if ok, e := c.VerifyResponseSign(res); !ok {
		return e
	}

	if res.Data == "" {
		return
	}

	if result == nil {
		return
	}

	content, err := decryptWithPKCS1v15(res.Data, c.appPrivateKey)
	if err != nil {
		return NewError(CDataDecryptFailure).SetErr(err)
	}

	c.logger.Infof("Shucang api data decrypted content: %s", content)

	err = json.Unmarshal(content, result)
	if err != nil {
		return NewError(CDataDecodeFailure).SetErr(err)
	}

	return
}

func (c *Client) DoRequest(method string, param Param, result interface{}) *BizErr {
	return c.doRequest(method, param, result)
}

func (c *Client) VerifyResponseSign(res *Response) (bool, *BizErr) {
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

func (c *Client) VerifyRequestSign(req *Request) (bool, *BizErr) {
	var data = url.Values{}
	data.Add("app_id", req.AppId)
	data.Add("method", req.Method)
	data.Add("nonce", req.Nonce)
	data.Add("timestamp", req.Timestamp)
	data.Add("sign", req.Sign)
	data.Add("data", req.Data)

	return c.VerifySign(data)
}

func (c *Client) VerifySign(data url.Values) (ok bool, e *BizErr) {
	ok, src, err := verifySign(data, c.todayPublicKey)
	if err != nil {
		c.logger.Infof("VerifySign sign string: %s", src)
		return ok, NewError(CSignFailure).SetErr(err)
	}
	return
}

func (c *Client) VerifyRequestParam(request *Request, p Param) *BizErr {
	if ok, err := c.VerifyRequestSign(request); !ok {
		return NewError(CSignFailure).SetErr(err)
	}

	content, e := c.DecryptRequestData(request)
	if e != nil {
		return e
	}

	err := json.Unmarshal([]byte(content), p)
	if err != nil {
		return NewError(CUnknown).SetErr(err)
	}

	return nil
}

func (c *Client) DecryptRequestData(request *Request) (ds string, e *BizErr) {
	if request.Data == "" {
		return
	}
	content, err := decryptWithPKCS1v15(request.Data, c.appPrivateKey)
	if err != nil {
		return "", NewError(CDataDecryptFailure).SetErr(err)
	}

	ds = string(content)

	return
}

func ParseRequest(req *http.Request) (r *Request, err error) {
	if req.ContentLength == 0 {
		return
	}

	ctype := req.Header.Get(HeaderContentType)
	switch {
	case strings.HasPrefix(ctype, MIMEApplicationJSON):
		err = json.NewDecoder(req.Body).Decode(&r)
		if ute, ok := err.(*json.UnmarshalTypeError); ok {
			err = fmt.Errorf("unmarshal type error: expected=%v, got=%v, field=%v, offset=%v", ute.Type, ute.Value, ute.Field, ute.Offset)
			return
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

		r = new(Request)
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

func verifySign(data url.Values, key *rsa.PublicKey) (ok bool, src string, err error) {
	sign := data.Get(kSignNodeName)

	src = toBeSignedString(data)
	ok, err = verifyData([]byte(src), sign, key)

	return
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

func signWithPKCS1v15(param url.Values, privateKey *rsa.PrivateKey, hash crypto.Hash) (s string, src string, err error) {
	src = toBeSignedString(param)
	sig, err := crypto4go.RSASignWithKey([]byte(src), privateKey, hash)
	if err != nil {
		return
	}
	s = base64.StdEncoding.EncodeToString(sig)
	return
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

func Nonce() string {
	id := uuid.New().String()
	r := sha1.Sum([]byte(id))
	return hex.EncodeToString(r[:])
}
