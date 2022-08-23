package shucang

type CollectionPublishCancelNotifyParam struct {
	CollectionHash string `json:"collection_hash"`
	CancelTime     int64  `json:"cancel_time"`
	SaleId         int64  `json:"sale_id"`
}

func (r CollectionPublishCancelNotifyParam) APIName() string {
	return MCollectionPublishCancelNotify
}

// CollectionPublishCancelNotify 取消藏品发布通知
func (c *Client) CollectionPublishCancelNotify(param CollectionPublishCancelNotifyParam) *BizErr {
	return c.doRequest("POST", param, nil)
}
