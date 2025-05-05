package types

// User структура для авторизации
type CreateUserRequest struct {
	UUID     string `json:"uuid"`
	Login    string `json:"login"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

type UserData struct {
	Login string `json:"login"`
	UUID  string `db:"uuid"`
	Hash  string `db:"hash"`
}

// SensitiveData представляет структуру для хранения различных типов данных
type SensitiveData struct {
	DataID      int64       `db:"data_id" json:"data_id"` // ID добавленной записи
	UUID        string      `db:"uuid" json:"uuid"`       // ID пользователя в системе
	Credentials Credentials `db:"credentials" json:"credentials"`
	TextData    TextData    `db:"text_data" json:"text_data"`     // Произвольные текстовые данные
	BinaryData  BinaryData  `db:"binary_data" json:"binary_data"` // Произвольные бинарные данные
	CardDetails CardDetails `db:"card_details" json:"card_details"`
}

// ClientSaveRequest запрос клиента на сохранение данных
type ClientSaveRequest struct {
	Credentials Credentials `json:"credentials"`
	TextData    TextData    `json:"text_data"`   // Произвольные текстовые данные
	BinaryData  BinaryData  `json:"binary_data"` // Произвольные бинарные данные
	CardDetails CardDetails `json:"card_details"`
}

// Credentials пары логин пароль которые будет хранить пользователь
type Credentials struct {
	Username string   `json:"username"`
	Password string   `json:"password"`
	Metadata Metadata `json:"metadata"`
}

// TextData произвольные текстовые данные
type TextData struct {
	TextData string   `json:"text_data"`
	Metadata Metadata `json:"metadata"`
}

// BinaryData произвольные бинарные данные
type BinaryData struct {
	BinaryData []byte   `json:"binary_data"`
	Metadata   Metadata `json:"metadata"`
}

// CardDetails данные банковских карт
type CardDetails struct {
	CardDetails string   `json:"card_details"`
	Metadata    Metadata `json:"metadata"`
}

type Metadata map[string]interface{}
