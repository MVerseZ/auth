
[![Rust](https://img.shields.io/badge/rust-1.70%2B-blue.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/github/license/MVerseZ/auth)](https://github.com/MVerseZ/auth/blob/master/LICENSE)
[![Axum](https://img.shields.io/badge/axum-0.7-red.svg)](https://github.com/tokio-rs/axum)
[![GitHub Stars](https://img.shields.io/github/stars/MVerseZ/auth)](https://github.com/MVerseZ/auth/stargazers)
[![GitHub Issues](https://img.shields.io/github/issues/MVerseZ/auth)](https://github.com/MVerseZ/auth/issues)
[![Docker Pulls](https://img.shields.io/badge/docker-available-blue?logo=docker)](https://hub.docker.com/r/yourusername/auth) <!-- Замените ссылку, если выложите образ -->
[![Crates.io](https://img.shields.io/badge/crates.io-not%20published-yellow)](https://crates.io/) <!-- Показывает, что пакет ещё не опубликован -->
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
