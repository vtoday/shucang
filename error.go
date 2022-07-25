package shucang

import "fmt"

type Code string

func (c Code) IsSuccess() bool {
	return c == CSuccess
}

const (
	CSuccess            Code = "200"  // 成功
	CDataDecryptFailure Code = "3001" // 数据解密失败
	CSignFailure        Code = "3002" // 签名校验失败
	CParamInvalid       Code = "4000" // 参数无效
	CNotAppIdParam      Code = "4001" // 缺少参数app_id
	CNotSignParam       Code = "4002" // 缺少参数sign
	CNotNonceParam      Code = "4003" // 缺少参数nonce
	CNotDataParam       Code = "4004" // 缺少业务参数
	CNotConfig          Code = "4005" // 缺少配置参数
	CCertError          Code = "4042" // 密钥或证书错误

	CTodayException    Code = "5001" // 交易平台服务异常
	CPlatformException Code = "5002" // 一级平台服务异常
	CDataDecodeFailure Code = "5003" // 数据解析失败
	CApiRequestFailure Code = "5004" // 接口请求失败
	CUnknown           Code = "5500" // 未知异常

)

var codeMessages = map[Code]string{
	CSuccess:            "成功",
	CDataDecryptFailure: "数据解密失败",
	CSignFailure:        "签名校验失败",
	CParamInvalid:       "参数无效",
	CNotAppIdParam:      "缺少参数app_id",
	CNotSignParam:       "缺少参数sign",
	CNotNonceParam:      "缺少参数nonce",
	CNotDataParam:       "缺少业务参数",
	CNotConfig:          "缺少配置参数",
	CCertError:          "密钥或证书错误",

	CTodayException:    "交易平台服务异常",
	CPlatformException: "一级平台服务异常",
	CDataDecodeFailure: "数据解析失败",
	CApiRequestFailure: "接口请求失败",
	CUnknown:           "未知异常",
}

type BizErr struct {
	Code    Code   `json:"code"`
	Message string `json:"message"`
	Err     error
}

func NewError(code Code, message ...string) *BizErr {
	bizErr := &BizErr{
		Code: code,
	}

	if len(message) > 0 {
		bizErr.Message = message[0]
	} else if msg, ok := codeMessages[code]; ok {
		bizErr.Message = msg
	} else {
		bizErr.Message = "未知"
	}

	return bizErr
}

func IsBizErr(err error) (*BizErr, bool) {
	e, ok := err.(*BizErr)
	if ok {
		return e, ok
	}
	return nil, false
}

func (r *BizErr) Error() string {
	return fmt.Sprintf("BizErr err, code: %s, message: %s, err: %+v", r.Code, r.Message, r.Err)
}

func (r *BizErr) SetErr(err error) *BizErr {
	r.Err = err
	return r
}
