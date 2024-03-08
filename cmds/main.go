package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.dfds.cloud/tool/ssu-aad-ephemeral-uri-updater/azure"
	"go.dfds.cloud/tool/ssu-aad-ephemeral-uri-updater/conf"
	"go.dfds.cloud/tool/ssu-aad-ephemeral-uri-updater/model"
	"go.dfds.cloud/tool/ssu-aad-ephemeral-uri-updater/model/static"
	"go.dfds.cloud/tool/ssu-aad-ephemeral-uri-updater/util"
	"go.uber.org/zap"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	config, err := conf.LoadConfig()
	if err != nil {
		panic(err)
	}

	store := &conf.StateStore{SetupCompleted: false, WebhookSecret: config.WebhookSecret, UriPrefix: config.UriPrefix, AzureTenantId: config.AzureTenantId, AzureClientId: config.AzureClientId, AzureAppId: config.AzureUpdateUriId}
	store.AzureClient = azure.NewAzureClient(azure.Config{
		TenantId:     config.AzureTenantId,
		ClientId:     config.AzureClientId,
		ClientSecret: config.AzureClientSecret,
		RedirectUri:  config.AzureRedirectUri,
	})

	router := gin.New()
	router.Use(gin.Recovery(), gin.ErrorLogger())
	router.Use(conf.AddStateStore(store))

	router.GET("/metrics", metricsHandler())
	router.GET("/setup", setupHandler())
	router.GET("/setup/return", setupReturnHandler())
	router.GET("/api/tenant", func(c *gin.Context) {
		store := conf.GetStateStore(c)
		payload := struct {
			TenantId string `json:"tenantId"`
			ClientId string `json:"clientId"`
		}{TenantId: store.AzureTenantId, ClientId: store.AzureClientId}
		serialised, err := json.Marshal(payload)
		if err != nil {
			c.String(500, "")
			return
		}
		c.String(200, string(serialised))
	})
	router.POST("/setup/submitCode", setupCodeHandler())
	router.POST("/hook", hookHandler())

	srv := &http.Server{
		Addr:    ":8080",
		Handler: router,
	}

	// HTTP server
	go func() {
		// service connections
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %s\n", err)
		}
	}()

	go worker(store)

	// Blocks until Context (ctx) is cancelled
	<-ctx.Done()

	if err := srv.Shutdown(ctx); err != nil {
		util.Logger.Info("HTTP Server was unable to shut down gracefully", zap.Error(err))
	}

	util.Logger.Info("Server shutting down")
}

func metricsHandler() gin.HandlerFunc {
	h := promhttp.Handler()

	return func(c *gin.Context) {
		h.ServeHTTP(c.Writer, c.Request)
	}
}

func setupHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		buf, err := static.GetFileFromBox("setup.html")
		if err != nil {
			c.String(400, "")
			return
		}

		c.Header("Content-Type", "text/html")
		c.String(200, string(buf))
	}
}

func setupReturnHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		buf, err := static.GetFileFromBox("setup_return.html")
		if err != nil {
			c.String(400, "")
			return
		}

		c.Header("Content-Type", "text/html")
		c.String(200, string(buf))
	}
}

func setupCodeHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		store := conf.GetStateStore(c)
		code := c.PostForm("code")
		util.Logger.Info("New auth code received from /setup, saving")

		resp, err := store.AzureClient.ConsumeAuthCode(code)
		if err != nil {
			util.Logger.Error("Refreshing Azure auth failed", zap.Error(err))
		}

		if resp == nil {
			c.String(400, "")
			return
		}

		store.AzureClient.TokenClient.Token.Token = resp.AccessToken
		store.AzureClient.TokenClient.Token.RefreshToken = resp.RefreshToken
		store.AzureClient.TokenClient.Token.ExpiresIn = resp.ExpiresIn + time.Now().Unix()
		store.AzureClient.TokenClient.RefreshTokenLastUsed = time.Now().Unix()

		store.SetupCompleted = true

		buf, err := static.GetFileFromBox("setup_post_return.html")
		if err != nil {
			c.String(400, "")
			return
		}

		c.Header("Content-Type", "text/html")
		c.String(200, string(buf))
	}
}

func signBody(secret, body []byte) []byte {
	computed := hmac.New(sha256.New, secret)
	computed.Write(body)
	return []byte(computed.Sum(nil))
}

func hookHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		util.Logger.Info("Hook triggered")
		store := conf.GetStateStore(c)
		ghSignatureHeader := c.GetHeader("X-Hub-Signature-256")
		signaturePrefix := "sha256="

		requestPayload, err := c.GetRawData()
		if err != nil {
			c.String(400, "")
			return
		}

		actual := make([]byte, sha256.Size)
		hex.Decode(actual, []byte(ghSignatureHeader[len(signaturePrefix):]))
		expected := signBody([]byte(store.WebhookSecret), requestPayload)

		if !hmac.Equal(expected, actual) {
			c.String(401, "")
			return
		}

		var prEvent model.GitHubPullRequestEvent
		err = json.Unmarshal(requestPayload, &prEvent)
		if err != nil {
			util.Logger.Error("Deserialising failed", zap.Error(err))
			c.String(500, "")
			return
		}

		if !store.SetupCompleted {
			c.String(200, "")
			util.Logger.Info("Setup not completed, skipping hook action")
			return
		}

		appResp, err := store.AzureClient.GetApplication(store.AzureAppId)
		if err != nil {
			util.Logger.Error(err.Error(), zap.Error(err))
			c.String(200, "")
			return
		}

		uriPrefix := store.UriPrefix
		const labelKey = "preview-env"
		redirectUris := appResp.Spa.RedirectUris
		branchSlug := slugifyBranch(prEvent.PullRequest.Head.Ref)
		prUri := fmt.Sprintf("%s%s", uriPrefix, branchSlug)

		switch prEvent.Action {
		case "opened":
			util.Logger.Info(fmt.Sprintf("'%s' PR opened at %s", prEvent.PullRequest.Title, prEvent.Repository.Name))
			containsLabel := false
			for _, labelObj := range prEvent.PullRequest.Labels {
				if labelObj.Name == labelKey {
					containsLabel = true
				}
			}

			if !containsLabel {
				c.String(200, "")
				return
			}

			err = addUri(store, branchSlug, prUri, redirectUris)
			if err != nil {
				util.Logger.Error(err.Error(), zap.Error(err))
				c.String(200, "")
				return
			}
		case "reopened":
			util.Logger.Info(fmt.Sprintf("'%s' PR reopened at %s", prEvent.PullRequest.Title, prEvent.Repository.Name))
			containsLabel := false
			for _, labelObj := range prEvent.PullRequest.Labels {
				if labelObj.Name == labelKey {
					containsLabel = true
				}
			}

			if !containsLabel {
				c.String(200, "")
				return
			}
			err = addUri(store, branchSlug, prUri, redirectUris)
			if err != nil {
				util.Logger.Error(err.Error(), zap.Error(err))
				c.String(200, "")
				return
			}
		case "closed":
			util.Logger.Info(fmt.Sprintf("'%s' PR closed at %s", prEvent.PullRequest.Title, prEvent.Repository.Name))
			fmt.Println(prEvent.PullRequest.Labels)
			err = removeUri(store, branchSlug, prUri, redirectUris)
			if err != nil {
				util.Logger.Error(err.Error(), zap.Error(err))
				c.String(200, "")
				return
			}
		case "labeled":
			if prEvent.PullRequest.State == "closed" {
				c.String(200, "")
				return
			}
			util.Logger.Info(fmt.Sprintf("%s added to %s", prEvent.Label.Name, prEvent.Repository.Name))
			if prEvent.Label.Name == labelKey {
				err = addUri(store, branchSlug, prUri, redirectUris)
				if err != nil {
					util.Logger.Error(err.Error(), zap.Error(err))
					c.String(200, "")
					return
				}
			}
		case "unlabeled":
			if prEvent.PullRequest.State == "closed" {
				c.String(200, "")
				return
			}
			util.Logger.Info(fmt.Sprintf("%s removed from %s", prEvent.Label.Name, prEvent.Repository.Name))
			if prEvent.Label.Name == labelKey {
				err = removeUri(store, branchSlug, prUri, redirectUris)
				if err != nil {
					util.Logger.Error(err.Error(), zap.Error(err))
					c.String(200, "")
					return
				}
			}
		}

		c.String(200, "")
	}
}

func addUri(store *conf.StateStore, slug string, uri string, redirectUris []string) error {
	if !containsString(slug, redirectUris) {
		util.Logger.Info("URI for new PR not found in app registration, adding")
		newRedirectUris := addUriToSlice(uri, redirectUris)
		util.Logger.Debug("old redirectURIs", zap.Strings("redirectUris", redirectUris))
		util.Logger.Debug("new redirectURIs", zap.Strings("redirectUris", newRedirectUris))
		payload := azure.PatchApplicationSpaRedirectUri{Spa: azure.PatchApplicationSpaRedirectUriSpa{RedirectUris: newRedirectUris}}
		serialised, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		err = store.AzureClient.PatchApplication(store.AzureAppId, serialised)
		if err != nil {
			return err
		}

		util.Logger.Info("URI added to app registration")
	}

	return nil
}

func removeUri(store *conf.StateStore, slug string, uri string, redirectUris []string) error {
	if containsString(slug, redirectUris) {
		util.Logger.Info("URI for closed PR found in app registration, removing")
		newRedirectUris := removeUriFromSlice(uri, redirectUris)
		util.Logger.Debug("old redirectURIs", zap.Strings("redirectUris", redirectUris))
		util.Logger.Debug("new redirectURIs", zap.Strings("redirectUris", newRedirectUris))
		payload := azure.PatchApplicationSpaRedirectUri{Spa: azure.PatchApplicationSpaRedirectUriSpa{RedirectUris: newRedirectUris}}
		serialised, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		err = store.AzureClient.PatchApplication(store.AzureAppId, serialised)
		if err != nil {
			return err
		}

		util.Logger.Info("URI removed from app registration")
	}

	return nil
}

func slugifyBranch(value string) string {
	payload := value

	payload = strings.ReplaceAll(payload, "/", "-")
	payload = firstN(payload, 23)

	return payload
}

func firstN(str string, n int) string {
	v := []rune(str)
	if n >= len(v) {
		return str
	}
	return string(v[:n])
}

func containsString(input string, data []string) bool {
	for _, val := range data {
		if strings.Contains(val, input) {
			return true
		}
	}
	return false
}

func removeUriFromSlice(uri string, data []string) []string {
	newSlice := []string{}
	for _, val := range data {
		if !strings.Contains(val, uri) {
			newSlice = append(newSlice, val)
		}
	}
	return newSlice
}

func addUriToSlice(uri string, data []string) []string {
	data = append(data, uri)
	return data
}

func worker(store *conf.StateStore) {
	util.InitializeLogger()
	config, err := conf.LoadConfig()
	if err != nil {
		panic(err)
	}

	sleepInterval, err := time.ParseDuration(fmt.Sprintf("%ds", config.WorkerInterval))
	if err != nil {
		panic(err)
	}

	for {
		util.Logger.Info("Worker started")

		// Check if app has all the necessary data to operate
		if config.AzureUpdateUriId == "" || config.AzureClientId == "" || config.AzureClientSecret == "" || config.AzureRedirectUri == "" {
			util.Logger.Error("Mandatory configuration missing, can't continue, terminating service")
			os.Exit(1)
		}

		if !store.SetupCompleted {
			util.Logger.Error("No valid user session available. Please visit /setup to continue")
			time.Sleep(sleepInterval)
			continue
		}

		// Ensure refresh tokens are kept alive
		if store.AzureClient.TokenClient.Token.RefreshToken != "" && time.Now().After(time.Unix(store.AzureClient.TokenClient.RefreshTokenLastUsed, 0).Add(48*time.Hour)) {
			util.Logger.Info("RefreshToken hasn't been used for the last 48 hours, acquiring new refresh token", zap.Time("refreshTokenLastUsed", time.Unix(store.AzureClient.TokenClient.RefreshTokenLastUsed, 0)), zap.String("refreshTokenLastUsedString", time.Unix(store.AzureClient.TokenClient.RefreshTokenLastUsed, 0).String()))
		}

		if store.AzureClient.TokenClient.Token.RefreshToken != "" && store.AzureClient.TokenClient.Token == nil {
			util.Logger.Info("RefreshToken exists, but no AccessToken is stored, retrieving AccessToken")
			azClient := azure.NewAzureClient(azure.Config{
				TenantId:     config.AzureTenantId,
				ClientId:     config.AzureClientId,
				ClientSecret: config.AzureClientSecret,
				RedirectUri:  config.AzureRedirectUri,
			})
			err = azClient.RefreshAuth(true)
			if err != nil {
				util.Logger.Error("Refreshing Azure auth failed", zap.Error(err))
			}
		}

		if store.AzureClient.TokenClient.Token != nil {
			if !store.AzureClient.TokenClient.Token.IsExpired() {
				_, err := store.AzureClient.GetApplication(config.AzureUpdateUriId)
				if err != nil {
					util.Logger.Error("GetApplication failed", zap.Error(err))
					continue
				}
			} else {
				util.Logger.Info("AccessToken expired, renewing")
				err = store.AzureClient.RefreshAuth(true)
				if err != nil {
					util.Logger.Error("Refreshing Azure auth failed", zap.Error(err))
				}
			}
		}

		util.Logger.Info(fmt.Sprintf("Worker stopped, waiting %f seconds before starting worker again", sleepInterval.Seconds()))
		time.Sleep(sleepInterval)
	}
}
