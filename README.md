# auth

Простой сервер аутентификации на Rust с Axum.

## Запуск

1. Скопируйте пример окружения:
   ```bash
   copy .env.example .env
   ```
2. При необходимости измените значение `JWT_SECRET`.
3. Запустите сервер:
   ```bash
   cargo run
   ```

## Docker

```bash
docker build -t auth:latest .
docker run -p 3000:3000 --env-file .env auth:latest
```

## CI

Проект автоматически запускает тесты через GitHub Actions при push/PR.

## API

- `POST /register` — регистрация пользователя
- `POST /login` — вход, возвращает access и refresh токены
- `POST /refresh` — обновление access токена по refresh токену
- `POST /logout` — выход с инвалидированием токена
- `GET /me` — получение информации о текущем пользователе
