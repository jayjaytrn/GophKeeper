# GophKeeper Server

Серверная часть системы GophKeeper — безопасное хранилище пользовательских приватных данных (пароли, текст, файлы и т.д.).

## Запуск

### 1. Поднять PostgreSQL

### 2. Сборка и запуск сервера

```bash
go build -o gophkeeper-server ./cmd/server
./gophkeeper-server -a :8080 -d postgres://postgres:postgres@localhost:5432/gophkeeper?sslmode=disable -j your_secret_key
```

или с конфигом:

```bash
./gophkeeper-server -c config.json
```

## ⚙️ Переменные окружения

Можно использовать `.env` или переменные окружения напрямую:

| Переменная       | Описание                          |
| ---------------- | --------------------------------- |
| `SERVER_ADDRESS` | Адрес запуска (например, `:8080`) |
| `DATABASE_DSN`   | DSN для PostgreSQL                |
| `JWT_SECRET`     | Секрет для подписи JWT            |
| `ENABLE_HTTPS`   | Включить HTTPS (`true/false`)     |

## Эндпоинты

* `POST /api/register` — регистрация
* `POST /api/login` — логин
* `GET /data` — получить все записи
* `GET /data/{id}` — получить запись по ID
* `POST /data` — сохранить данные
