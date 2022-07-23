package shucang

import (
	"fmt"
)

const (
	kSandboxURL    = "https://dev-openapi.360ex.art/api/v1/open"
	kProductionURL = "https://openapi.360ex.art/api/v1/open"
	kContentType   = "application/json;charset=utf-8"
	kTimeFormat    = "2006-01-02 15:04:05"
	kSignNodeName  = "sign"
)

const (
	MUserInfo                     = "user.info"
	MCollectionInfo               = "collection.info"
	MCollectionExchange           = "collection.exchange"
	MCollectionExchangeInfo       = "collection.exchange.info"
	MCollectionPublishNotify      = "collection.publish.notify"
	MCollectionTradeSuccessNotify = "collection.trade.success.notify"
	MCollectionExtract            = "collection.extract"
	MCenterCollectionCheck        = "center.collection.check"
)

type Code string

func (c Code) IsSuccess() bool {
	return c == CodeSuccess
}

const (
	CodeSuccess Code = "200" // 接口调用成功
)

type Param interface {
	// APIName 用于提供访问的 method
	APIName() string
}

type Response struct {
	Code      Code   `json:"code"`
	Message   string `json:"message"`
	Method    string `json:"method"`
	Nonce     string `json:"nonce"`
	Timestamp string `json:"timestamp"`
	Sign      string `json:"sign"`
	Data      string `json:"data"`
}

func (r *Response) Error() string {
	return fmt.Sprintf("Response err, code: %s, message: %s", r.Code, r.Message)
}
