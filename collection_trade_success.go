package shucang

type CollectionTradeSuccessParams struct {
	CollectionHash string `json:"collection_hash"`
	Price          string `json:"price"`
	CompleteTime   string `json:"complete_time"`
}

func (r CollectionTradeSuccessParams) APIName() string {
	return MCollectionTradeSuccessNotify
}

// CollectionTradeSuccessNotify 藏品售买成功通知
func (c *Client) CollectionTradeSuccessNotify(param CollectionTradeSuccessParams) *BizErr {
	return c.doRequest("POST", param, nil)
}
