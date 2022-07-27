package shucang

type CollectionPublishNotifyParam struct {
	CollectionHash string `json:"collection_hash"`
	Price          int64  `json:"price"`
	PublishTime    int64  `json:"publish_time"`
}

func (r CollectionPublishNotifyParam) APIName() string {
	return MCollectionPublishNotify
}

// CollectionPublishNotify 流转藏品
func (c *Client) CollectionPublishNotify(param CollectionPublishNotifyParam) *BizErr {
	return c.doRequest("POST", param, nil)
}
