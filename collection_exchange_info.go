package shucang

type CollectionExchangeInfoParam struct {
	CollectionHash string `json:"collection_hash"`
}

func (r CollectionExchangeInfoParam) APIName() string {
	return MCollectionExchangeInfo
}

type CollectionExchangeInfoResponse struct {
	ProductId             string `json:"product_id"`
	ProductName           string `json:"product_name"`
	ProductCount          int64  `json:"product_count"`
	ProductAddress        string `json:"product_address"`
	ProductPicture        string `json:"product_picture"`
	ProductDetail         string `json:"product_detail"`
	ProductCirculationNum int64  `json:"product_circulation_num"`
	ProductPublishedTime  int64  `json:"product_published_time"`
	CollectionNumber      int64  `json:"collection_number"`
	CollectionHash        string `json:"collection_hash"`
	OwnerUserId           string `json:"owner_user_id"`
	OwnerWalletAddress    string `json:"owner_wallet_address"`
	MakerId               string `json:"maker_id"`
	MakerName             string `json:"maker_name"`
	MakerPicture          string `json:"maker_picture"`
	ExchangeUserId        string `json:"exchange_user_id"`
	ExchangeWalletAddress string `json:"exchange_wallet_address"`
}

func (r CollectionExchangeInfoResponse) APIName() string {
	return MCollectionExchangeInfo
}

// CollectionExchangeInfo 查询正在转入(寄售)藏品信息
func (c *Client) CollectionExchangeInfo(param CollectionExchangeInfoParam) (result *CollectionExchangeInfoResponse, err *BizErr) {
	err = c.doRequest("POST", param, result)
	return
}
