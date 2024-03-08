package model

import "time"

type BearerToken struct {
	Token        string
	RefreshToken string
	ExpiresIn    int64
}

func (b *BearerToken) IsExpired() bool {
	if b.Token == "" {
		return true
	}

	currentTime := time.Now()
	tokenExpirationTime := time.Unix(b.ExpiresIn, 0)
	return currentTime.After(tokenExpirationTime)
}

func (b *BearerToken) GetToken() string {
	return b.Token
}

func NewBearerToken(token string) *BearerToken {
	return &BearerToken{Token: token}
}
