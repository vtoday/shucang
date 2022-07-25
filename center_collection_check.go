package shucang

type CenterCollectionCheckParam struct {
	CollectionHash string `json:"collection_hash"`
}

func (r CenterCollectionCheckParam) APIName() string {
	return MCenterCollectionCheck
}

type CenterCollectionCheckResponse struct {
	IsExist            string `json:"is_exist"`
	OwnerWalletAddress string `json:"owner_wallet_address"`
}

func (r CenterCollectionCheckResponse) APIName() string {
	return MCenterCollectionCheck
}

// CenterCollectionCheck 查询用户信息
func (c *Client) CenterCollectionCheck(param CenterCollectionCheckParam) (result *CenterCollectionCheckResponse, err error) {
	err = c.doRequest("POST", param, result)
	return
}