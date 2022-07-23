package shucang

type UserInfoParam struct {
	Name  string `json:"name"`
	Phone string `json:"phone"`
}

func (r UserInfoParam) APIName() string {
	return MUserInfo
}

type UserInfoResponse struct {
	UserId        string `json:"user_id"`
	WalletAddress string `json:"wallet_address"`
	VerifySign    string `json:"verify_sign"`
}

func (r UserInfoResponse) APIName() string {
	return MUserInfo
}

// UserInfo 查询用户信息
func (c *Client) UserInfo(param UserInfoParam) (result *UserInfoResponse, err error) {
	err = c.doRequest("POST", param, result)
	return
}
