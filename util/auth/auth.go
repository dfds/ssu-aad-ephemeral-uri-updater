package auth

import (
	"errors"
	"go.dfds.cloud/tool/ssu-aad-ephemeral-uri-updater/util/auth/model"
	"sync"
	"time"
)

type RefreshAuthResponse struct {
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	ExtExpiresIn int64  `json:"ext_expires_in"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type TokenClient struct {
	Token                *model.BearerToken
	RefreshTokenLastUsed int64
	refreshAuthFunc      func(string) (*RefreshAuthResponse, error)
	mu                   sync.Mutex
}

func NewTokenClient(authFunc func(string) (*RefreshAuthResponse, error)) *TokenClient {
	return &TokenClient{
		Token:           &model.BearerToken{},
		refreshAuthFunc: authFunc,
	}
}

func (c *TokenClient) RefreshAuth(forceRenewal bool) error {
	if c.Token != nil {
		if !forceRenewal {
			if !c.Token.IsExpired() {
				//fmt.Println("Token has not expired, reusing token from cache")
				return nil
			}
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	resp, err := c.refreshAuthFunc(c.Token.RefreshToken)
	if err != nil {
		return err
	}
	if resp == nil {
		return errors.New("unable to refresh authentication")
	}

	currentTime := time.Now()
	c.RefreshTokenLastUsed = currentTime.Unix()
	c.Token = &model.BearerToken{}
	c.Token.ExpiresIn = currentTime.Unix() + resp.ExpiresIn
	c.Token.Token = resp.AccessToken
	c.Token.RefreshToken = resp.RefreshToken

	return nil
}
