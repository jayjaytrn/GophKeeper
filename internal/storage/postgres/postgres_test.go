package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jayjaytrn/gophkeeper/config"
	"github.com/jayjaytrn/gophkeeper/internal/types"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
	"testing"
)

func setup(t *testing.T) (*Manager, sqlmock.Sqlmock, func()) {
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	cfg := &config.Config{}
	return &Manager{db: db, cfg: cfg}, mock, func() { db.Close() }
}

func TestGetData(t *testing.T) {
	manager, mock, close := setup(t)
	defer close()

	credJSON, _ := json.Marshal(types.Credentials{Username: "user"})
	textJSON, _ := json.Marshal(types.TextData{TextData: "note"})
	binJSON, _ := json.Marshal(types.BinaryData{BinaryData: []byte("bin")})
	cardJSON, _ := json.Marshal(types.CardDetails{CardDetails: "card"})

	rows := sqlmock.NewRows([]string{"data_id", "uuid", "credentials", "text_data", "binary_data", "card_details"}).
		AddRow(1, "uuid-123", credJSON, textJSON, binJSON, cardJSON)

	mock.ExpectQuery("SELECT data_id, uuid, credentials").
		WithArgs(int64(1)).
		WillReturnRows(rows)

	result, err := manager.GetData(context.Background(), 1)
	assert.NoError(t, err)
	assert.Equal(t, "uuid-123", result.UUID)
}

func TestCreateData_Success(t *testing.T) {
	manager, mock, close := setup(t)
	defer close()

	data := &types.SensitiveData{
		UUID:        "uuid-123",
		Credentials: types.Credentials{Username: "user"},
		TextData:    types.TextData{TextData: "note"},
		BinaryData:  types.BinaryData{BinaryData: []byte("bin")},
		CardDetails: types.CardDetails{CardDetails: "card"},
	}

	mock.ExpectQuery("INSERT INTO sensitive_data").
		WithArgs("uuid-123", sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"data_id"}).AddRow(10))

	id, err := manager.CreateData(context.Background(), data)
	assert.NoError(t, err)
	assert.Equal(t, int64(10), id)
}

func TestCreateData_MarshalError(t *testing.T) {
	manager, _, close := setup(t)
	defer close()

	data := &types.SensitiveData{
		UUID: "uuid-123",
		Credentials: types.Credentials{
			Metadata: map[string]interface{}{
				"bad": func() {}, // cannot be marshaled
			},
		},
	}

	_, err := manager.CreateData(context.Background(), data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "marshal")
}

func TestGetData_NotFound(t *testing.T) {
	manager, mock, close := setup(t)
	defer close()

	mock.ExpectQuery("SELECT data_id, uuid, credentials").
		WithArgs(int64(99)).
		WillReturnError(sql.ErrNoRows)

	_, err := manager.GetData(context.Background(), 99)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestGetData_UnmarshalError(t *testing.T) {
	manager, mock, close := setup(t)
	defer close()

	badJSON := []byte("{invalid")
	rows := sqlmock.NewRows([]string{"data_id", "uuid", "credentials", "text_data", "binary_data", "card_details"}).
		AddRow(1, "uuid-123", badJSON, badJSON, badJSON, badJSON)

	mock.ExpectQuery("SELECT data_id, uuid, credentials").
		WithArgs(int64(1)).
		WillReturnRows(rows)

	_, err := manager.GetData(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unmarshal")
}

func TestGetAllData_Success(t *testing.T) {
	manager, mock, close := setup(t)
	defer close()

	credJSON, _ := json.Marshal(types.Credentials{Username: "user"})
	textJSON, _ := json.Marshal(types.TextData{TextData: "note"})
	binJSON, _ := json.Marshal(types.BinaryData{BinaryData: []byte("bin")})
	cardJSON, _ := json.Marshal(types.CardDetails{CardDetails: "card"})

	rows := sqlmock.NewRows([]string{"data_id", "uuid", "credentials", "text_data", "binary_data", "card_details"}).
		AddRow(1, "uuid-123", credJSON, textJSON, binJSON, cardJSON)

	mock.ExpectQuery("SELECT data_id, uuid, credentials").
		WithArgs("uuid-123").
		WillReturnRows(rows)

	list, err := manager.GetAllData(context.Background(), "uuid-123")
	assert.NoError(t, err)
	assert.Len(t, list, 1)
	assert.Equal(t, "uuid-123", list[0].UUID)
}

func TestGetAllData_Empty(t *testing.T) {
	manager, mock, close := setup(t)
	defer close()

	mock.ExpectQuery("SELECT data_id, uuid, credentials").
		WithArgs("empty-user").
		WillReturnRows(sqlmock.NewRows([]string{"data_id", "uuid", "credentials", "text_data", "binary_data", "card_details"}))

	_, err := manager.GetAllData(context.Background(), "empty-user")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no data found")
}

func TestGetAllData_RowScanError(t *testing.T) {
	manager, mock, close := setup(t)
	defer close()

	rows := sqlmock.NewRows([]string{"data_id", "uuid", "credentials", "text_data", "binary_data"}). // missing card_details
														AddRow(1, "uuid-123", "{}", "{}", "[]")

	mock.ExpectQuery("SELECT data_id, uuid, credentials").
		WithArgs("uuid-123").
		WillReturnRows(rows)

	_, err := manager.GetAllData(context.Background(), "uuid-123")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "scan row")
}

func TestCreateUser_Success(t *testing.T) {
	manager, mock, close := setup(t)
	defer close()

	mock.ExpectExec("INSERT INTO users").
		WithArgs("login", "uuid", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err := manager.CreateUser(context.Background(), types.CreateUserRequest{
		Login:    "login",
		UUID:     "uuid",
		Password: "pass123",
	})
	assert.NoError(t, err)
}

func TestGetUUIDByHash_Success(t *testing.T) {
	manager, mock, close := setup(t)
	defer close()

	hash, _ := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.DefaultCost)

	mock.ExpectQuery("SELECT uuid, hash FROM users").
		WillReturnRows(sqlmock.NewRows([]string{"uuid", "hash"}).
			AddRow("user-uuid", string(hash)))

	uuid, err := manager.GetUUIDByHash(context.Background(), "secret")
	assert.NoError(t, err)
	assert.Equal(t, "user-uuid", uuid)
}

func TestGetUUIDByHash_Fail(t *testing.T) {
	manager, mock, close := setup(t)
	defer close()

	mock.ExpectQuery("SELECT uuid, hash FROM users").
		WillReturnRows(sqlmock.NewRows([]string{"uuid", "hash"}).
			AddRow("u1", "wronghash"))

	_, err := manager.GetUUIDByHash(context.Background(), "secret")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no user found")
}

func TestCreateUser_ExecError(t *testing.T) {
	manager, mock, close := setup(t)
	defer close()

	mock.ExpectExec("INSERT INTO users").
		WithArgs("login", "uuid", sqlmock.AnyArg()).
		WillReturnError(errors.New("exec failed"))

	err := manager.CreateUser(context.Background(), types.CreateUserRequest{
		Login:    "login",
		UUID:     "uuid",
		Password: "123",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exec")
}

func TestGetUUIDByHash_QueryError(t *testing.T) {
	manager, mock, close := setup(t)
	defer close()

	mock.ExpectQuery("SELECT uuid, hash FROM users").
		WillReturnError(errors.New("query failed"))

	_, err := manager.GetUUIDByHash(context.Background(), "123")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "query")
}

func TestGetUUIDByHash_ScanError(t *testing.T) {
	manager, mock, close := setup(t)
	defer close()

	rows := sqlmock.NewRows([]string{"uuid"}).AddRow("uuid-only")
	mock.ExpectQuery("SELECT uuid, hash FROM users").
		WillReturnRows(rows)

	_, err := manager.GetUUIDByHash(context.Background(), "123")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "scan")
}

func TestGetUUIDByHash_RowErr(t *testing.T) {
	manager, mock, close := setup(t)
	defer close()

	rows := sqlmock.NewRows([]string{"uuid", "hash"}).
		AddRow("uuid", "badhash").
		RowError(0, errors.New("row error"))

	mock.ExpectQuery("SELECT uuid, hash FROM users").
		WillReturnRows(rows)

	_, err := manager.GetUUIDByHash(context.Background(), "123")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "rows error")
}

func TestCreateGophKeeperTable_Error(t *testing.T) {
	manager, mock, close := setup(t)
	defer close()

	mock.ExpectExec("CREATE TABLE IF NOT EXISTS sensitive_data").
		WillReturnError(errors.New("db error"))

	err := manager.createGophKeeperTable()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "sensitive_data")
}

func TestCreateUserTable_Error(t *testing.T) {
	manager, mock, close := setup(t)
	defer close()

	mock.ExpectExec("CREATE TABLE IF NOT EXISTS users").
		WillReturnError(errors.New("db error"))

	err := manager.createUserTable()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "users")
}

func TestGetAllData_UnmarshalTextError(t *testing.T) {
	manager, mock, close := setup(t)
	defer close()

	cred, _ := json.Marshal(types.Credentials{Username: "user"})
	bad := []byte("{invalid")
	card, _ := json.Marshal(types.CardDetails{CardDetails: "card"})

	rows := sqlmock.NewRows([]string{"data_id", "uuid", "credentials", "text_data", "binary_data", "card_details"}).
		AddRow(1, "uuid", cred, bad, []byte(`{}`), card)

	mock.ExpectQuery("SELECT data_id, uuid, credentials").
		WithArgs("uuid").
		WillReturnRows(rows)

	_, err := manager.GetAllData(context.Background(), "uuid")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unmarshal text_data")
}

func TestGetAllData_RowsErr(t *testing.T) {
	manager, mock, close := setup(t)
	defer close()

	cred, _ := json.Marshal(types.Credentials{Username: "user"})
	text, _ := json.Marshal(types.TextData{TextData: "note"})
	bin, _ := json.Marshal(types.BinaryData{BinaryData: []byte("bin")})
	card, _ := json.Marshal(types.CardDetails{CardDetails: "card"})

	rows := sqlmock.NewRows([]string{"data_id", "uuid", "credentials", "text_data", "binary_data", "card_details"}).
		AddRow(1, "uuid", cred, text, bin, card).
		RowError(0, errors.New("rows error"))

	mock.ExpectQuery("SELECT data_id, uuid, credentials").
		WithArgs("uuid").
		WillReturnRows(rows)

	_, err := manager.GetAllData(context.Background(), "uuid")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "rows error")
}

func TestGetData_ScanError(t *testing.T) {
	manager, mock, close := setup(t)
	defer close()

	rows := sqlmock.NewRows([]string{"data_id", "uuid", "credentials", "text_data", "binary_data"}). // не хватает card_details
														AddRow(1, "uuid-123", "{}", "{}", "{}")

	mock.ExpectQuery("SELECT data_id, uuid, credentials").
		WithArgs(int64(1)).
		WillReturnRows(rows)

	_, err := manager.GetData(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "scan")
}

func TestGetData_UnmarshalBinaryError(t *testing.T) {
	manager, mock, close := setup(t)
	defer close()

	cred, _ := json.Marshal(types.Credentials{Username: "user"})
	text, _ := json.Marshal(types.TextData{TextData: "note"})
	card, _ := json.Marshal(types.CardDetails{CardDetails: "card"})

	badJSON := []byte("{not-json")

	rows := sqlmock.NewRows([]string{"data_id", "uuid", "credentials", "text_data", "binary_data", "card_details"}).
		AddRow(1, "uuid-123", cred, text, badJSON, card)

	mock.ExpectQuery("SELECT data_id, uuid, credentials").
		WithArgs(int64(1)).
		WillReturnRows(rows)

	_, err := manager.GetData(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unmarshal binary_data")
}

func TestGetAllData_UnmarshalCardError(t *testing.T) {
	manager, mock, close := setup(t)
	defer close()

	cred, _ := json.Marshal(types.Credentials{Username: "user"})
	text, _ := json.Marshal(types.TextData{TextData: "note"})
	bin, _ := json.Marshal(types.BinaryData{BinaryData: []byte("bin")})

	badCard := []byte("{bad-json")

	rows := sqlmock.NewRows([]string{"data_id", "uuid", "credentials", "text_data", "binary_data", "card_details"}).
		AddRow(1, "uuid-123", cred, text, bin, badCard)

	mock.ExpectQuery("SELECT data_id, uuid, credentials").
		WithArgs("uuid-123").
		WillReturnRows(rows)

	_, err := manager.GetAllData(context.Background(), "uuid-123")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unmarshal card_details")
}

func TestClose_DB(t *testing.T) {
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)

	cfg := &config.Config{}
	manager := &Manager{db: db, cfg: cfg}

	mock.ExpectClose()

	err = manager.Close(context.Background())
	assert.NoError(t, err)

	assert.NoError(t, mock.ExpectationsWereMet())
}
