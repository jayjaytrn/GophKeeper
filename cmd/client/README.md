
# GophKeeper CLI Client

CLI-клиент для безопасного хранения и получения данных с сервера GophKeeper.

## Сборка

```bash
go build -o gophkeeper-client
````

## Команды

```bash
./gophkeeper-client <command> [args]
```

### Авторизация

```bash
./gophkeeper-client register
./gophkeeper-client login
```

### Работа с данными

```bash
./gophkeeper-client save           # сохранить данные
./gophkeeper-client list         # получить все данные
./gophkeeper-client get <id>       # получить запись по ID
```

### Версия

```bash
./gophkeeper-client version
```

##  Пример использования

```bash
./gophkeeper-client register
./gophkeeper-client save
./gophkeeper-client getall
```
