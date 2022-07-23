package shucang

type Exchange struct {
	CollectionHash     string
	OwnerWalletAddress string
	UserId             string
}

func (r Exchange) APIName() string {
	return "collection.exchange"
}
