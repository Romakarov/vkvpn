# VKVPN — Генеральный план развития

## Что это за проект

VPN-система, туннелирующая WireGuard-трафик через TURN-серверы VK Звонков и Yandex Telemost. ISP видит обычный видеозвонок, а не VPN. Двухслойная обфускация: DTLS-шифрование + TURN-реле через легитимную инфраструктуру.

### Архитектура

```
[Устройство] ← WireGuard → [Локальный UDP :9000]
                                    ↓
                              [DTLS клиент]
                                    ↓
                        [TURN-реле VK/Yandex]
                                    ↓
                              [VPS :56000]
                                    ↓
                              [DTLS сервер]
                                    ↓
                        [WireGuard :51820] → Интернет
```

### Компоненты

| Компонент | Путь | Язык | Строк | Статус |
|-----------|------|------|-------|--------|
| Сервер | `server/main.go` | Go | 852 | Продакшн |
| Клиент | `client/main.go` | Go | 849 | Продакшн |
| Android-туннель | `android/tunnel/tunnel.go` | Go (gomobile) | 848 | Продакшн |
| Android-UI | `android/app/src/` | Kotlin | 350 | Продакшн |
| Пакетный пайп | `pkg/packetpipe/pipe.go` | Go | 86 | Продакшн |
| Веб-админка | `server/web/index.html` | HTML/JS | 547 | Продакшн |
| CI/CD | `.github/workflows/build-apk.yml` | YAML | — | Работает |
| Деплой | `deploy.sh`, `install.sh` | Bash | — | Работает |

### Текущие тесты

- `server/config_test.go` — конфигурация, аллокация IP, генерация WG-конфигов (5 тестов)
- `server/log_test.go` — кольцевой буфер логов (2 теста)
- `pkg/packetpipe/pipe_test.go` — пакетный пайп (3 теста)
- **Итого: ~10 тестов, покрытие минимальное**

---

## Приоритет 1 — Критические улучшения

### 1.1 README.md
**Файл:** корень проекта
**Что сделать:**
- Описание проекта и принципа работы
- Архитектурная схема (ASCII или Mermaid)
- Инструкция по развёртыванию сервера (VPS, Ubuntu 24.04)
- Инструкция по подключению клиентов (macOS, Linux, Windows, Android)
- API-документация сервера (все эндпоинты)
- Требования: Go 1.25+, WireGuard, Ubuntu 24.04

### 1.2 HTTPS для веб-админки
**Файл:** `server/main.go`
**Проблема:** Админка на HTTP :8080, пароль летит в открытом виде.
**Решение:**
- Автогенерация самоподписанного TLS-сертификата (или Let's Encrypt через `-domain` флаг)
- Флаг `-tls-cert` / `-tls-key` для своих сертификатов
- Redirect HTTP → HTTPS
- HSTS header

### 1.3 Валидация DTLS-сертификатов (Certificate Pinning)
**Файлы:** `server/main.go`, `client/main.go`, `android/tunnel/tunnel.go`
**Проблема:** `InsecureSkipVerify: true` — MITM-атака тривиальна.
**Решение:**
- Сервер генерирует стабильный сертификат (не при каждом запуске)
- Fingerprint сертификата включается в конфиг клиента
- Клиент проверяет fingerprint при DTLS-хэндшейке
- Добавить поле `dtls_fingerprint` в `/api/clients/appconfig`

### 1.4 Вынести дублированный код VK/Yandex credentials
**Файлы:** `client/main.go`, `android/tunnel/tunnel.go`
**Проблема:** Код извлечения TURN-credentials дублируется в 2 местах (client и android tunnel) — около 300 строк × 2.
**Решение:**
- Создать `pkg/turnauth/vk.go` и `pkg/turnauth/yandex.go`
- Единый интерфейс `GetCredentials(link string) (*TURNCredentials, error)`
- Использовать в обоих клиентах
- **Важно:** gomobile не поддерживает все Go-типы, нужно обернуть для Android

---

## Приоритет 2 — Тестирование и CI

### 2.1 Тесты серверных API-хэндлеров
**Файл:** создать `server/handlers_test.go`
**Что покрыть:**
- `GET /api/status` — корректный JSON, все поля
- `POST /api/clients/add` — создание клиента, дубликат имени, лимит IP
- `POST /api/clients/delete` — удаление, несуществующий клиент
- `POST /api/clients/toggle` — включение/выключение
- `GET /api/clients/config` — формат WireGuard-конфига
- `GET /api/clients/appconfig` — формат JSON-конфига
- `POST /api/link` — установка TURN-ссылки
- Авторизация: без токена, с неверным токеном

### 2.2 Тесты клиентского кода
**Файл:** создать `client/main_test.go`
**Что покрыть:**
- Парсинг CLI-флагов
- DTLS-конфигурация (генерация сертификата)
- Формат TURN-запросов (mock HTTP)
- Packet forwarding логика

### 2.3 CI для Go-тестов
**Файл:** создать `.github/workflows/test.yml`
**Содержание:**
```yaml
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: '1.25' }
      - run: go test ./server/ ./pkg/... -v -race
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: golangci/golangci-lint-action@v6
```

### 2.4 golangci-lint
**Файл:** создать `.golangci.yml`
**Линтеры:** `errcheck`, `govet`, `staticcheck`, `unused`, `gosimple`, `ineffassign`

---

## Приоритет 3 — Надёжность и мониторинг

### 3.1 Health check эндпоинт
**Файл:** `server/main.go`
**Эндпоинт:** `GET /api/health`
**Ответ:**
```json
{
  "status": "ok",
  "wireguard": true,
  "dtls_listener": true,
  "uptime_seconds": 86400,
  "clients_connected": 3,
  "version": "2.1.0"
}
```

### 3.2 Метрики и статистика
**Файл:** `server/main.go` (или вынести в `server/metrics.go`)
**Что считать:**
- Общий трафик (bytes in/out) через DTLS
- Количество активных DTLS-соединений
- Количество WireGuard-пиров online (через `wg show`)
- Uptime сервера
- Последнее время подключения каждого клиента
**API:** `GET /api/metrics` с JSON-ответом
**Опционально:** Prometheus-совместимый `/metrics` эндпоинт

### 3.3 Graceful shutdown
**Файл:** `server/main.go`
**Что сделать:**
- Обработка SIGTERM/SIGINT
- Закрытие DTLS-listener
- Сохранение конфигурации перед выходом
- Лог "shutting down gracefully"

### 3.4 Кэширование TURN-credentials
**Файлы:** `client/main.go`, `android/tunnel/tunnel.go`
**Проблема:** Каждое подключение запрашивает TURN-credentials заново (5 HTTP-запросов для VK).
**Решение:**
- Кэшировать credentials с TTL (VK: ~12 часов, Yandex: ~1 час)
- При ошибке — перезапрашивать
- Логировать время жизни credentials

### 3.5 Reconnect logic
**Файлы:** `client/main.go`, `android/tunnel/tunnel.go`
**Проблема:** При обрыве TURN-соединения нет автоматического реконнекта.
**Решение:**
- Экспоненциальный backoff (1s, 2s, 4s, 8s, max 30s)
- Перезапрос credentials при ошибке авторизации
- Логирование попыток реконнекта
- Максимум попыток: настраиваемо (по умолчанию: бесконечно)

---

## Приоритет 4 — Безопасность

### 4.1 Rate limiting на API
**Файл:** `server/main.go`
**Что ограничить:**
- `/api/clients/add` — 10 req/min
- `/api/link` — 5 req/min
- Неавторизованные запросы — 30 req/min на IP
**Реализация:** простой token bucket на `sync.Map`

### 4.2 Хэширование админского пароля
**Файл:** `server/main.go`
**Проблема:** `AdminPass` хранится в plaintext в `/etc/vkvpn/config.json`.
**Решение:**
- Хранить bcrypt-хэш
- При первом запуске: сгенерировать пароль → вывести в stdout → сохранить хэш
- Сравнение через `bcrypt.CompareHashAndPassword`

### 4.3 Генерация WireGuard-ключей без CLI
**Файл:** `server/main.go`
**Проблема:** `wgGenKey()` вызывает `exec.Command("wg", "genkey")` — зависимость от внешнего бинарника, потенциальная инъекция.
**Решение:**
- Использовать `golang.zx2c4.com/wireguard/wgctrl/wgtypes` для генерации ключей
- Или `crypto/rand` + Curve25519 напрямую (32 байта random → clamp → base64)

### 4.4 Input validation
**Файл:** `server/main.go`
**Что валидировать:**
- Имя клиента: `^[a-zA-Z0-9_-]{1,64}$`
- TURN-ссылка: URL-формат, домен в allowlist (vk.com, telemost.yandex.ru)
- Размер тела запроса: ≤ 1MB
- Content-Type проверка

---

## Приоритет 5 — Функциональность

### 5.1 Multi-link поддержка
**Файлы:** `server/main.go`, `server/web/index.html`
**Сейчас:** Сервер хранит один `ActiveLink` + `LinkType`.
**Цель:**
- Список TURN-ссылок с приоритетами
- Клиент получает несколько ссылок в конфиге
- Failover: если одна ссылка не работает, пробовать следующую
- Раунд-робин или weighted random

### 5.2 Статистика по клиентам в админке
**Файлы:** `server/main.go`, `server/web/index.html`
**Что показать:**
- Последний handshake (из `wg show wg0 latest-handshakes`)
- Трафик: bytes sent/received (из `wg show wg0 transfer`)
- Онлайн/оффлайн индикатор (handshake < 3 минут = онлайн)

### 5.3 QR-код для мобильного конфига
**Файлы:** `server/main.go`, `server/web/index.html`
**Сейчас:** QR-код генерируется на клиенте (qrencode).
**Цель:** Генерация QR-кода прямо в веб-админке для `/api/clients/appconfig`

### 5.4 iOS-клиент
**Путь:** `ios/` (новая директория)
**Подход:**
- SwiftUI приложение
- wireguard-go через gomobile (как Android)
- Переиспользование `android/tunnel/tunnel.go` (или общий `pkg/tunnel/`)
- Network Extension для VPN

### 5.5 Автообновление клиентов
**Файлы:** `server/main.go`, `client/main.go`
**Решение:**
- `GET /api/version` — текущая версия сервера
- Клиент при старте проверяет версию
- `GET /api/download/{platform}` — скачать обновлённый бинарник
- Self-update через замену бинарника

---

## Приоритет 6 — Инфраструктура

### 6.1 Docker-контейнеризация сервера
**Файл:** создать `Dockerfile`
```dockerfile
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y wireguard wireguard-tools
COPY server /opt/vkvpn/server
COPY install.sh /opt/vkvpn/install.sh
EXPOSE 56000/udp 8080/tcp 51820/udp
CMD ["/opt/vkvpn/server", "-config", "/etc/vkvpn/config.json"]
```
**Примечание:** WireGuard требует NET_ADMIN capability и доступ к `/dev/net/tun`

### 6.2 CI для серверного бинарника
**Файл:** расширить `.github/workflows/` или создать `build-server.yml`
**Содержание:**
- Сборка для linux/amd64 и linux/arm64
- Загрузка в GitHub Releases
- Версионирование через git tags

### 6.3 Автоматический деплой через SSH MCP
**Инструменты:** ssh-mcp-server (установлен в `/opt/node22/bin/ssh-mcp-server`)
**Конфигурация:** `/root/.mcp.json`
**Цель:** Агент может деплоить на VPS автономно через MCP SSH

### 6.4 Бэкап конфигурации
**Файл:** `server/main.go` или отдельный скрипт
**Что бэкапить:**
- `/etc/vkvpn/config.json` — клиенты, ключи
- `/etc/wireguard/wg0.conf` — WireGuard конфиг
**Куда:** Локальная папка `/etc/vkvpn/backups/` с ротацией (7 дней)

---

## Технический долг

### Дублирование кода
- **VK credentials:** `client/main.go:38-130` ≈ `android/tunnel/tunnel.go:38-130`
- **Yandex credentials:** `client/main.go:132-373` ≈ `android/tunnel/tunnel.go:132-373`
- **DTLS setup:** `client/main.go:375-399` ≈ `android/tunnel/tunnel.go` (аналогичный код)
- **Packet pipe:** `pkg/packetpipe/pipe.go` vs inline в `android/tunnel/tunnel.go`
- **Решение:** Общий пакет `pkg/turnauth/` + переиспользование `pkg/packetpipe/`

### Hardcoded секреты
- VK Client ID: `6287487` в `client/main.go` и `android/tunnel/tunnel.go`
- VK Client Secret: `QbYic1K3lEV5kTGiqlq2` там же
- **Решение:** Вынести в конфиг или env-переменные (но они публичные для VK API, так что риск низкий)

### Panic recovery antipattern
- `client/main.go` — `getVkCreds()` делает `defer func() { recover() }` вместо нормальной обработки ошибок
- **Решение:** Заменить на `error` return

### Отсутствие версионирования
- Нет `version` переменной в бинарниках
- Нет git tags для релизов
- **Решение:** `go build -ldflags "-X main.version=..."` + GitHub Releases

---

## Зависимости проекта

### Go (основной модуль)
```
github.com/pion/dtls/v3 v3.1.2          # DTLS протокол
github.com/pion/turn/v5 v5.0.3          # TURN клиент
github.com/pion/logging v0.2.4          # Логирование
github.com/gorilla/websocket v1.5.3     # WebSocket (Yandex)
github.com/google/uuid v1.6.0           # UUID
```

### Go (Android tunnel)
```
golang.zx2c4.com/wireguard              # wireguard-go библиотека
golang.org/x/mobile                     # gomobile binding
(+ всё из основного модуля)
```

### Android
```
compileSdk: 35 (Android 15)
minSdk: 26 (Android 8.0)
Kotlin: 2.1.0
AGP: 8.7.3
NDK: 27.2.12479018
```

---

## Установленные MCP-серверы

| MCP | Путь | Назначение |
|-----|------|------------|
| ssh-mcp-server | `/opt/node22/bin/ssh-mcp-server` | SSH к VPS для деплоя |
| WireMCP | `/opt/WireMCP/index.js` | Анализ сетевого трафика (tshark) |
| GitHub MCP | встроен | PR, issues, code search |
| Notion MCP | встроен | Документация |
| Canva MCP | встроен | Дизайн |

Конфигурация: `/root/.mcp.json`

---

## Порядок работы для агентов

1. **Прочитай этот файл** целиком перед началом работы
2. **Прочитай CLAUDE.md** если есть — там могут быть дополнительные инструкции
3. **Ветка разработки:** `claude/review-project-status-H9z3p` (или создай новую по задаче)
4. **Коммитить** после каждого логического шага, не копить изменения
5. **Тесты:** запускай `go test ./server/ ./pkg/... -v` перед коммитом
6. **Не трогай** `releases/` — бинарники обновляются вручную
7. **Не ломай** существующий API — обратная совместимость важна

### Быстрый старт для агента
```bash
cd /home/user/vkvpn
go test ./server/ ./pkg/... -v          # Прогнать тесты
go build ./server/                       # Собрать сервер
go build ./client/                       # Собрать клиент
```

### Ключевые файлы для чтения
```
server/main.go              # Весь сервер (API + DTLS + WireGuard)
client/main.go              # Весь клиент (TURN + DTLS)
android/tunnel/tunnel.go    # Android-туннель (дубликат клиента)
server/web/index.html       # Веб-админка
deploy.sh                   # Скрипт деплоя
install.sh                  # Скрипт установки на VPS
.github/workflows/build-apk.yml  # CI для APK
```
