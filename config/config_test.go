package config

import (
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetConfig(t *testing.T) {
	// очищаем флаги перед запуском теста
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	// задаём переменные окружения
	os.Setenv("SERVER_ADDRESS", "0.0.0.0:9090")
	os.Setenv("DATABASE_DSN", "postgres://env")
	os.Setenv("STORAGE_TYPE", "postgres")

	// задаём путь к JSON-файлу через переменную окружения CONFIG
	tmpFile := filepath.Join(t.TempDir(), "config.json")
	_ = os.WriteFile(tmpFile, []byte(`{"log_level":"debug","token_ttl":"99h"}`), 0644)
	os.Setenv("CONFIG", tmpFile)

	// сбрасываем и задаём флаги
	os.Args = []string{
		"test",
		"-a=127.0.0.1:8088",
		"-d=postgres://cli",
		"-t=15m",
		"-l=warn",
		"-storage=cli",
	}

	cfg := GetConfig()

	assert.Equal(t, "0.0.0.0:9090", cfg.ServerAddress)
	assert.Equal(t, "postgres://env", cfg.DatabaseDSN)
	assert.Equal(t, "15m", cfg.TokenTTL)
	assert.Equal(t, "warn", cfg.LogLevel)
	assert.Equal(t, "postgres", cfg.StorageType)
}

func TestLoadFromJSON_Success(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "config.json")
	content := `{
		"server_address": "127.0.0.1:9000",
		"database_dsn": "postgres://user:pass@localhost/db",
		"enable_https": true,
		"tls_cert_path": "/cert.pem",
		"tls_key_path": "/key.pem",
		"token_ttl": "30m",
		"log_level": "debug",
		"sync_interval": "1m",
		"build_version": "v1.2.3",
		"build_date": "2025-05-06",
		"storage_type": "postgres"
	}`

	err := os.WriteFile(tmpFile, []byte(content), 0644)
	assert.NoError(t, err)

	cfg, err := loadFromJSON(tmpFile)
	assert.NoError(t, err)
	assert.Equal(t, "127.0.0.1:9000", cfg.ServerAddress)
	assert.Equal(t, "postgres://user:pass@localhost/db", cfg.DatabaseDSN)
	assert.True(t, cfg.EnableHTTPS)
	assert.Equal(t, "debug", cfg.LogLevel)
	assert.Equal(t, "postgres", cfg.StorageType)
}

func TestLoadFromJSON_FileNotFound(t *testing.T) {
	_, err := loadFromJSON("non-existent-file.json")
	assert.Error(t, err)
}

func TestMergeConfig(t *testing.T) {
	base := &Config{
		ServerAddress: "localhost:8080",
	}
	file := &Config{
		ServerAddress: "127.0.0.1:9000",
		DatabaseDSN:   "postgres://test",
		LogLevel:      "debug",
	}
	mergeConfig(base, file)

	assert.Equal(t, "localhost:8080", base.ServerAddress) // не перезаписывается
	assert.Equal(t, "postgres://test", base.DatabaseDSN)  // пустое поле — заполняется
	assert.Equal(t, "debug", base.LogLevel)
}
