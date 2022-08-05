package shucang

type CollectionExchangeInfoParam struct {
	CollectionHash string `json:"collection_hash"`
}

func (r CollectionExchangeInfoParam) APIName() string {
	return MCollectionExchangeInfo
}

type CollectionExchangeInfoResponse struct {
	ProductId             string `json:"product_id"`
	CollectionNumber      int64  `json:"collection_number"`
	CollectionHash        string `json:"collection_hash"`
	ExchangeUserId        string `json:"exchange_user_id"`
	ExchangeWalletAddress string `json:"exchange_wallet_address"`
}

func (r CollectionExchangeInfoResponse) APIName() string {
	return MCollectionExchangeInfo
}

// CollectionExchangeInfo 查询正在转入(寄售)藏品信息
func (c *Client) CollectionExchangeInfo(param CollectionExchangeInfoParam) (result *CollectionExchangeInfoResponse, err *BizErr) {
	err = c.doRequest("POST", param, &result)
	return
}
