package conf

import (
	"github.com/gin-gonic/gin"
	"github.com/kelseyhightower/envconfig"
	"go.dfds.cloud/tool/ssu-aad-ephemeral-uri-updater/azure"
)

type Config struct {
	WorkerInterval    int    `json:"workerInterval"`
	AzureUpdateUriId  string `json:"azureUpdateUriId"`
	AzureTenantId     string `json:"azureTenantId"`
	AzureClientId     string `json:"azureClientId"`
	AzureClientSecret string `json:"azureClientSecret"`
	AzureRedirectUri  string `json:"azureRedirectUri"`
	UriPrefix         string `json:"uriPrefix"`
	WebhookSecret     string `json:"webhookSecret"`
	Log               struct {
		Level string `json:"level"`
		Debug bool   `json:"debug"`
	}
}

const APP_CONF_PREFIX = "SAEUU"

func LoadConfig() (Config, error) {
	var conf Config
	err := envconfig.Process(APP_CONF_PREFIX, &conf)

	if conf.WorkerInterval == 0 {
		conf.WorkerInterval = 60
	}

	return conf, err
}

type StateStore struct {
	AzureClient    *azure.Client
	AzureAppId     string
	AzureClientId  string
	SetupCompleted bool
	WebhookSecret  string
	UriPrefix      string
	AzureTenantId  string
}

func AddStateStore(s *StateStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Keys == nil {
			c.Keys = map[string]any{}
		}
		c.Keys["state"] = s
	}
}

func GetStateStore(c *gin.Context) *StateStore {
	item, _ := c.Get("state")
	o := item.(*StateStore)
	return o
}
