package shucang

type UserBindNotifyParam struct {
	UserId                string `json:"user_id"`
	PlatformUserId        string `json:"platform_user_id"`
	PlatformWalletAddress string `json:"platform_wallet_address"`
	Type                  int64  `json:"type"`
}

func (r UserBindNotifyParam) APIName() string {
	return MUserBindNotify
}

// UserBindNotify 用户绑定/解绑通知
func (c *Client) UserBindNotify(param UserBindNotifyParam) (err *BizErr) {
	err = c.doRequest("POST", param, nil)
	return
}
