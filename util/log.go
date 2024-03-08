package util

import (
	"fmt"
	conf2 "go.dfds.cloud/tool/ssu-aad-ephemeral-uri-updater/conf"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var Logger *zap.Logger

func InitializeLogger() {
	conf, _ := conf2.LoadConfig()

	var logConf zap.Config
	if conf.Log.Debug {
		logConf = zap.NewDevelopmentConfig()
	} else {
		logConf = zap.NewProductionConfig()
	}

	level, err := zapcore.ParseLevel(conf.Log.Level)
	if err != nil {
		fmt.Println(err)
		level = zapcore.InfoLevel
	}

	logConf.Level = zap.NewAtomicLevelAt(level)

	Logger, _ = logConf.Build(zap.AddStacktrace(zapcore.ErrorLevel))
	Logger.Info(fmt.Sprintf("Logging enabled, log level set to %s", Logger.Level().String()))
}
