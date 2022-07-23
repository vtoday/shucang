package shucang

type CollectionExchangeParam struct {
	CollectionHash     string `json:"collection_hash"`
	OwnerWalletAddress string `json:"owner_wallet_address"`
	UserId             string `json:"user_id"`
}

func (r CollectionExchangeParam) APIName() string {
	return MCollectionExchange
}

// Exchange 流转藏品
func (c *Client) Exchange(param CollectionExchangeParam) error {
	return c.doRequest("POST", param, nil)
}
