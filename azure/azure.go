package azure

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"go.dfds.cloud/tool/ssu-aad-ephemeral-uri-updater/util/auth"
	modelAuth "go.dfds.cloud/tool/ssu-aad-ephemeral-uri-updater/util/auth/model"
	"go.dfds.cloud/utils/config"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type Client struct {
	httpClient  *http.Client
	TokenClient *auth.TokenClient
	config      Config
}

type Config struct {
	TenantId     string `json:"tenantId"`
	ClientId     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
	RedirectUri  string `json:"redirectUri"`
}

func (c *Client) RefreshAuth(forceRenewal bool) error {
	envToken := config.GetEnvValue("AAS_AZURE_TOKEN", "")
	if envToken != "" {
		c.TokenClient.Token = modelAuth.NewBearerToken(envToken)
		return nil
	}

	err := c.TokenClient.RefreshAuth(forceRenewal)
	return err
}

func (c *Client) getNewToken(code string) (*auth.RefreshAuthResponse, error) {
	reqPayload := url.Values{}
	reqPayload.Set("client_id", c.config.ClientId)
	reqPayload.Set("client_secret", c.config.ClientSecret)
	reqPayload.Set("redirect_uri", c.config.RedirectUri)
	reqPayload.Set("grant_type", "refresh_token")
	reqPayload.Set("scope", "offline_access .default")
	reqPayload.Set("refresh_token", code)

	req, err := http.NewRequest("POST", fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", c.config.TenantId), strings.NewReader(reqPayload.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	rawData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		fmt.Println(resp.StatusCode)
		fmt.Println(string(rawData))
		return nil, err
	}

	var tokenResponse *auth.RefreshAuthResponse

	err = json.Unmarshal(rawData, &tokenResponse)
	if err != nil {
		return nil, err
	}

	return tokenResponse, nil
}

func (c *Client) ConsumeAuthCode(code string) (*auth.RefreshAuthResponse, error) {
	reqPayload := url.Values{}
	reqPayload.Set("client_id", c.config.ClientId)
	reqPayload.Set("client_secret", c.config.ClientSecret)
	reqPayload.Set("redirect_uri", c.config.RedirectUri)
	reqPayload.Set("grant_type", "authorization_code")
	reqPayload.Set("scope", "offline_access .default")
	reqPayload.Set("code", code)

	req, err := http.NewRequest("POST", fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", c.config.TenantId), strings.NewReader(reqPayload.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	rawData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, err
	}

	var tokenResponse *auth.RefreshAuthResponse

	err = json.Unmarshal(rawData, &tokenResponse)
	if err != nil {
		return nil, err
	}

	return tokenResponse, nil
}

func (c *Client) prepareHttpRequest(req *http.Request) error {
	err := c.RefreshAuth(false)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.TokenClient.Token.GetToken()))
	req.Header.Set("User-Agent", "ssu-aad-ephemeral-uri-updater - github.com/dfds")
	return nil
}

func (c *Client) prepareJsonRequest(req *http.Request) error {
	err := c.prepareHttpRequest(req)
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	return nil
}

func (c *Client) GetApplication(appId string) (*GetApplicationResponse, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("https://graph.microsoft.com/v1.0/applications/%s", appId), nil)
	if err != nil {
		return nil, err
	}
	err = c.prepareHttpRequest(req)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	rawData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var payload *GetApplicationResponse

	err = json.Unmarshal(rawData, &payload)
	if err != nil {
		return nil, err
	}

	return payload, nil
}

func (c *Client) PatchApplication(appId string, data []byte) error {
	req, err := http.NewRequest("PATCH", fmt.Sprintf("https://graph.microsoft.com/v1.0/applications/%s", appId), bytes.NewBuffer(data))
	if err != nil {
		return err
	}

	err = c.prepareJsonRequest(req)
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode != 204 {
		errMsg := fmt.Sprintf("unexpected status code for patching application %d", resp.StatusCode)
		return errors.New(errMsg)
	}

	return nil
}

func NewAzureClient(conf Config) *Client {
	payload := &Client{
		httpClient: http.DefaultClient,
		config:     conf,
	}

	payload.TokenClient = auth.NewTokenClient(payload.getNewToken)

	return payload
}
