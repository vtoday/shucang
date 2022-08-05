package shucang

type CollectionInfoSyncParam struct {
	ProductId             string `json:"product_id"`
	ProductName           string `json:"product_name"`
	ProductCount          int64  `json:"product_count"`
	ProductAddress        string `json:"product_address"`
	ProductPicture        string `json:"product_picture"`
	ProductDetail         string `json:"product_detail"`
	ProductCirculationNum int64  `json:"product_circulation_num"`
	ProductPublishedTime  int64  `json:"product_published_time"`
	MakerId               string `json:"maker_id"`
	MakerName             string `json:"maker_name"`
	MakerPicture          string `json:"maker_picture"`
	PublishPrice          int64  `json:"publish_price"`
}

func (r CollectionInfoSyncParam) APIName() string {
	return MCollectionInfoSync
}

// CollectionInfoSync 同步藏品信息
func (c *Client) CollectionInfoSync(param CollectionInfoSyncParam) (err *BizErr) {
	err = c.doRequest("POST", param, nil)
	return
}
