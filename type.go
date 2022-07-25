package shucang

const (
	kSandboxURL       = "https://dev-openapi.360ex.art/api/v1/open"
	kProductionURL    = "https://openapi.360ex.art/api/v1/open"
	kContentType      = "application/json;charset=utf-8"
	kTimeFormat       = "2006-01-02 15:04:05"
	kSignNodeName     = "sign"
	HeaderContentType = "Content-Type"
	defaultMemory     = 32 << 20 // 32 MB

	MIMEApplicationJSON = "application/json"
	MIMEApplicationForm = "application/x-www-form-urlencoded"
	MIMEMultipartForm   = "multipart/form-data"
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

type Param interface {
	// APIName 用于提供访问的 method
	APIName() string
}

type Request struct {
	AppId     string `json:"app_id"`
	Method    string `json:"method"`
	Nonce     string `json:"nonce"`
	Timestamp string `json:"timestamp"`
	Sign      string `json:"sign"`
	Data      string `json:"data"`
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
