package storage

import (
	"github.com/jayjaytrn/gophkeeper/config"
	"github.com/jayjaytrn/gophkeeper/internal/storage/postgres"
	"go.uber.org/zap"
)

// GetStorage initializes and returns a storage manager based on the configured storage type.
func GetStorage(cfg *config.Config, logger *zap.SugaredLogger) DBStorage {
	// Initialize PostgreSQL-based storage
	if cfg.StorageType == "postgres" {
		logger.Debug("using postgres storage")
		s, err := postgres.NewManager(cfg)
		if err != nil {
			logger.Fatalw("failed to initialize postgres storage", "error", err)
		}
		return s
	}

	// Handle unknown storage types
	logger.Fatalw("unknown storage type", "type", cfg.StorageType)
	return nil
}
