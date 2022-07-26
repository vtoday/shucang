package shucang

type CollectionExtractParams struct {
	CollectionHash string `json:"collection_hash"`
	WalletAddress  string `json:"wallet_address"`
	UserId         string `json:"user_id"`
}

func (r CollectionExtractParams) APIName() string {
	return MCollectionExtract
}

// CollectionExtract 提取藏品至指定账户
func (c *Client) CollectionExtract(param CollectionExtractParams) *BizErr {
	return c.doRequest("POST", param, nil)
}
