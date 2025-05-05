package config

import (
	"encoding/json"
	"flag"
	"github.com/jayjaytrn/gophkeeper/logging"
	"os"

	"github.com/caarlos0/env/v6"
)

// Config stores configuration settings for the GophKeeper server.
type Config struct {
	ServerAddress string `env:"SERVER_ADDRESS,required" json:"server_address"` // Server listen address
	EnableHTTPS   bool   `env:"ENABLE_HTTPS" json:"enable_https"`              // Enable HTTPS
	TLSCertPath   string `env:"TLS_CERT_PATH" json:"tls_cert_path"`            // Path to TLS certificate
	TLSKeyPath    string `env:"TLS_KEY_PATH" json:"tls_key_path"`              // Path to TLS private key

	DatabaseDSN string `env:"DATABASE_DSN,required" json:"database_dsn"` // PostgreSQL DSN

	TokenTTL     string `env:"TOKEN_TTL" json:"token_ttl"`         // JWT token time-to-live (e.g., "15m")
	LogLevel     string `env:"LOG_LEVEL" json:"log_level"`         // Logging level (debug, info, warn, error)
	SyncInterval string `env:"SYNC_INTERVAL" json:"sync_interval"` // Optional background sync interval (e.g., "1m")

	BuildVersion string `json:"build_version"`                   // Build version (set via -ldflags)
	BuildDate    string `json:"build_date"`                      // Build date (set via -ldflags)
	StorageType  string `env:"STORAGE_TYPE" json:"storage_type"` // StorageType type of storage
}

// GetConfig initializes and returns the application configuration.
func GetConfig() *Config {
	logger := logging.GetSugaredLogger()
	defer logger.Sync()

	config := &Config{}
	configFilePath := flag.String("c", os.Getenv("CONFIG"), "path to config file")

	// CLI flags
	flag.StringVar(&config.ServerAddress, "a", "localhost:8080", "server listen address")
	flag.StringVar(&config.DatabaseDSN, "d", "", "PostgreSQL DSN")
	flag.StringVar(&config.TokenTTL, "t", "15m", "JWT token TTL")
	flag.BoolVar(&config.EnableHTTPS, "s", false, "enable HTTPS")
	flag.StringVar(&config.TLSCertPath, "cert", "", "path to TLS certificate")
	flag.StringVar(&config.TLSKeyPath, "key", "", "path to TLS private key")
	flag.StringVar(&config.LogLevel, "l", "info", "log level")
	flag.StringVar(&config.SyncInterval, "i", "", "sync interval (optional)")
	flag.StringVar(&config.StorageType, "storage", "", "storage type (e.g., postgres, memory, file)")

	flag.Parse()

	// Environment variables
	err := env.Parse(config)
	if err != nil {
		logger.Debug("failed to parse environment variables:", err)
	}

	// Config file (JSON)
	if *configFilePath != "" {
		jsonConfig, err := loadFromJSON(*configFilePath)
		if err != nil {
			logger.Debug("failed to load config from JSON:", err)
		} else {
			mergeConfig(config, jsonConfig)
		}
	}

	return config
}

// loadFromJSON reads configuration from a JSON file.
func loadFromJSON(filePath string) (*Config, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var cfg Config
	decoder := json.NewDecoder(file)
	if err = decoder.Decode(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// mergeConfig overrides empty fields in base config with values from file config.
func mergeConfig(base *Config, file *Config) {
	if base.ServerAddress == "" {
		base.ServerAddress = file.ServerAddress
	}
	if base.DatabaseDSN == "" {
		base.DatabaseDSN = file.DatabaseDSN
	}
	if base.TokenTTL == "" {
		base.TokenTTL = file.TokenTTL
	}
	if !base.EnableHTTPS {
		base.EnableHTTPS = file.EnableHTTPS
	}
	if base.TLSCertPath == "" {
		base.TLSCertPath = file.TLSCertPath
	}
	if base.TLSKeyPath == "" {
		base.TLSKeyPath = file.TLSKeyPath
	}
	if base.LogLevel == "" {
		base.LogLevel = file.LogLevel
	}
	if base.SyncInterval == "" {
		base.SyncInterval = file.SyncInterval
	}
	if base.BuildVersion == "" {
		base.BuildVersion = file.BuildVersion
	}
	if base.BuildDate == "" {
		base.BuildDate = file.BuildDate
	}
	if base.StorageType == "" {
		base.StorageType = file.StorageType
	}
}
