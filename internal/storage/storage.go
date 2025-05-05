package storage

import (
	"context"
	"github.com/jayjaytrn/gophkeeper/internal/types"
)

type DBStorage interface {
	// CreateData stores new sensitive information in the database.
	CreateData(ctx context.Context, data *types.SensitiveData) (int64, error)

	// GetData retrieves sensitive information by its ID.
	GetData(ctx context.Context, id int64) (*types.SensitiveData, error)

	// GetAllData retrieves all sensitive data for a given user.
	GetAllData(ctx context.Context, uuid string) ([]types.SensitiveData, error)

	// Close closes the connection to the storage.
	Close(ctx context.Context) error

	CreateUser(ctx context.Context, request types.CreateUserRequest) error

	GetUUIDByHash(ctx context.Context, password string) (string, error)
}
