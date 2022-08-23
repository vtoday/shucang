package shucang

type CollectionPublishNotifyParam struct {
	CollectionHash string `json:"collection_hash"`
	Price          int64  `json:"price"`
	PublishTime    int64  `json:"publish_time"`
	SaleId         int64  `json:"sale_id"`
}

func (r CollectionPublishNotifyParam) APIName() string {
	return MCollectionPublishNotify
}

// CollectionPublishNotify 藏品发布通知
func (c *Client) CollectionPublishNotify(param CollectionPublishNotifyParam) *BizErr {
	return c.doRequest("POST", param, nil)
}
