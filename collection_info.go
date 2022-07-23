package shucang

type CollectionInfoParam struct {
	CollectionHash string `json:"collection_hash"`
}

func (r CollectionInfoParam) APIName() string {
	return MCollectionInfo
}

type CollectionInfoResponse struct {
	ProductId             string `json:"product_id"`
	ProductName           string `json:"product_name"`
	ProductCount          string `json:"product_count"`
	ProductAddress        string `json:"product_address"`
	ProductPicture        string `json:"product_picture"`
	ProductDetail         string `json:"product_detail"`
	ProductCirculationNum string `json:"product_circulation_num"`
	ProductPublishedTime  string `json:"product_published_time"`
	CollectionNumber      string `json:"collection_number"`
	CollectionHash        string `json:"collection_hash"`
	OwnerUserId           string `json:"owner_user_id"`
	OwnerWalletAddress    string `json:"owner_wallet_address"`
	MakerId               string `json:"maker_id"`
	MakerName             string `json:"maker_name"`
	MakerPicture          string `json:"maker_picture"`
}

func (r CollectionInfoResponse) APIName() string {
	return MCollectionInfo
}

// CollectionInfo 查询藏品信息
func (c *Client) CollectionInfo(param CollectionInfoParam) (result *CollectionInfoResponse, err error) {
	err = c.doRequest("POST", param, result)
	return
}
