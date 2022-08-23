package shucang

type CollectionTradeSuccessParams struct {
	CollectionHash string `json:"collection_hash"`
	Price          int64  `json:"price"`
	CompleteTime   int64  `json:"complete_time"`
	SaleId         int64  `json:"sale_id"`
	OrderNo        string `json:"order_no"`
}

func (r CollectionTradeSuccessParams) APIName() string {
	return MCollectionTradeSuccessNotify
}

// CollectionTradeSuccessNotify 藏品售买成功通知
func (c *Client) CollectionTradeSuccessNotify(param CollectionTradeSuccessParams) *BizErr {
	return c.doRequest("POST", param, nil)
}
