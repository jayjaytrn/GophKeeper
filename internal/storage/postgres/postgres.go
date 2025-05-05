package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jayjaytrn/gophkeeper/config"
	"github.com/jayjaytrn/gophkeeper/internal/types"
	"golang.org/x/crypto/bcrypt"
)

// DataAlreadyExistsError represents an error when a sensitive data entry already exists.
type DataAlreadyExistsError struct {
	ExistingID int64
}

// Error returns the error message for DataAlreadyExistsError.
func (e *DataAlreadyExistsError) Error() string {
	return fmt.Sprintf("sensitive data already exists with ID: %d", e.ExistingID)
}

// Manager handles database interactions for URL shortening.
type Manager struct {
	db  *sql.DB
	cfg *config.Config
}

// NewManager creates a new Manager instance and connects to the database.
func NewManager(cfg *config.Config) (*Manager, error) {
	db, err := sql.Open("pgx", cfg.DatabaseDSN)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	if err = db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	manager := &Manager{
		db:  db,
		cfg: cfg,
	}

	if err = manager.createGophKeeperTable(); err != nil {
		return nil, fmt.Errorf("failed to create table: %w", err)
	}

	if err = manager.createUserTable(); err != nil {
		return nil, fmt.Errorf("failed to create table: %w", err)
	}

	return manager, nil
}

// CreateData stores new sensitive information in the database.
func (m *Manager) CreateData(ctx context.Context, data *types.SensitiveData) (int64, error) {
	query := `INSERT INTO sensitive_data (uuid, credentials, text_data, binary_data, card_details)
              VALUES ($1, $2, $3, $4, $5) RETURNING data_id`

	credentialsJSON, err := json.Marshal(data.Credentials)
	if err != nil {
		return 0, fmt.Errorf("failed to marshal credentials: %w", err)
	}

	textDataJSON, err := json.Marshal(data.TextData)
	if err != nil {
		return 0, fmt.Errorf("failed to marshal text data: %w", err)
	}

	binaryDataJSON, err := json.Marshal(data.BinaryData)
	if err != nil {
		return 0, fmt.Errorf("failed to marshal binary data: %w", err)
	}

	cardDetailsJSON, err := json.Marshal(data.CardDetails)
	if err != nil {
		return 0, fmt.Errorf("failed to marshal card details: %w", err)
	}

	var dataID int64
	err = m.db.QueryRowContext(ctx, query,
		data.UUID,
		credentialsJSON,
		textDataJSON,
		binaryDataJSON,
		cardDetailsJSON,
	).Scan(&dataID)

	if err != nil {
		return 0, fmt.Errorf("failed to insert data: %w", err)
	}
	return dataID, nil
}

// GetData retrieves sensitive information by its ID.
func (m *Manager) GetData(ctx context.Context, id int64) (*types.SensitiveData, error) {
	query := `SELECT data_id, uuid, credentials, text_data, binary_data, card_details 
              FROM sensitive_data WHERE data_id = $1`

	var (
		dataID      int64
		userUUID    string
		credJSON    []byte
		textJSON    []byte
		binaryBytes []byte
		cardJSON    []byte
	)

	row := m.db.QueryRowContext(ctx, query, id)
	err := row.Scan(&dataID, &userUUID, &credJSON, &textJSON, &binaryBytes, &cardJSON)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("data with ID %d not found", id)
		}
		return nil, fmt.Errorf("failed to scan data: %w", err)
	}

	var cred types.Credentials
	if err := json.Unmarshal(credJSON, &cred); err != nil {
		return nil, fmt.Errorf("unmarshal credentials: %w", err)
	}

	var text types.TextData
	if err := json.Unmarshal(textJSON, &text); err != nil {
		return nil, fmt.Errorf("unmarshal text_data: %w", err)
	}

	var card types.CardDetails
	if err := json.Unmarshal(cardJSON, &card); err != nil {
		return nil, fmt.Errorf("unmarshal card_details: %w", err)
	}

	var binary types.BinaryData
	if err := json.Unmarshal(binaryBytes, &binary); err != nil {
		return nil, fmt.Errorf("unmarshal binary_data: %w", err)
	}

	return &types.SensitiveData{
		DataID:      dataID,
		UUID:        userUUID,
		Credentials: cred,
		TextData:    text,
		BinaryData:  binary,
		CardDetails: card,
	}, nil
}

// GetAllData retrieves all sensitive data for a given user.
func (m *Manager) GetAllData(ctx context.Context, uuid string) ([]types.SensitiveData, error) {
	query := `SELECT data_id, uuid, credentials, text_data, binary_data, card_details
              FROM sensitive_data WHERE uuid = $1`

	rows, err := m.db.QueryContext(ctx, query, uuid)
	if err != nil {
		return nil, fmt.Errorf("failed to query data: %w", err)
	}
	defer rows.Close()

	var result []types.SensitiveData
	for rows.Next() {
		var (
			dataID      int64
			userUUID    string
			credJSON    []byte
			textJSON    []byte
			binaryBytes []byte
			cardJSON    []byte
		)

		err := rows.Scan(&dataID, &userUUID, &credJSON, &textJSON, &binaryBytes, &cardJSON)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		var cred types.Credentials
		if err := json.Unmarshal(credJSON, &cred); err != nil {
			return nil, fmt.Errorf("unmarshal credentials: %w", err)
		}

		var text types.TextData
		if err := json.Unmarshal(textJSON, &text); err != nil {
			return nil, fmt.Errorf("unmarshal text_data: %w", err)
		}

		var card types.CardDetails
		if err := json.Unmarshal(cardJSON, &card); err != nil {
			return nil, fmt.Errorf("unmarshal card_details: %w", err)
		}

		data := types.SensitiveData{
			DataID:      dataID,
			UUID:        userUUID,
			Credentials: cred,
			TextData:    text,
			BinaryData: types.BinaryData{
				BinaryData: binaryBytes,
				Metadata:   map[string]interface{}{},
			},
			CardDetails: card,
		}
		result = append(result, data)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("no data found for user: %s", uuid)
	}

	return result, nil
}

func (m *Manager) CreateUser(ctx context.Context, request types.CreateUserRequest) error {
	hashBytes, err := bcrypt.GenerateFromPassword([]byte(request.Password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hashing error: %w", err)
	}

	query := `INSERT INTO users (login, uuid, hash) VALUES ($1, $2, $3)`
	_, err = m.db.ExecContext(ctx, query, request.Login, request.UUID, string(hashBytes))
	if err != nil {
		return err
	}

	return nil
}

func (m *Manager) GetUUIDByHash(ctx context.Context, password string) (string, error) {
	const query = `SELECT uuid, hash FROM users`
	rows, err := m.db.QueryContext(ctx, query)
	if err != nil {
		return "", fmt.Errorf("query error: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var uuid, hash string
		if err := rows.Scan(&uuid, &hash); err != nil {
			return "", fmt.Errorf("scan error: %w", err)
		}
		if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err == nil {
			return uuid, nil
		}
	}

	if err := rows.Err(); err != nil {
		return "", fmt.Errorf("rows error: %w", err)
	}

	return "", fmt.Errorf("no user found for provided password")
}

// createGophKeeperTable ensures the sensitive_data table exists.
func (m *Manager) createGophKeeperTable() error {
	query := `
	CREATE TABLE IF NOT EXISTS sensitive_data (
		data_id SERIAL PRIMARY KEY,
		uuid TEXT NOT NULL,
		credentials JSONB,
		text_data JSONB,
		binary_data JSONB,
		card_details JSONB
	);`
	_, err := m.db.Exec(query)
	if err != nil {
		return fmt.Errorf("error creating sensitive_data table: %w", err)
	}
	return nil
}

func (m *Manager) createUserTable() error {
	query := `
	CREATE TABLE IF NOT EXISTS users (
		login TEXT PRIMARY KEY,
		uuid TEXT NOT NULL,
		hash TEXT NOT NULL
	);`
	_, err := m.db.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to create users table: %w", err)
	}
	return nil
}

// Close closes the database connection.
func (m *Manager) Close(ctx context.Context) error {
	return m.db.Close()
}
