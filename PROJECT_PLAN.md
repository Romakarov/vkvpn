# VKVPN — Генеральный план развития

## Что это за проект

VPN-система, туннелирующая WireGuard-трафик через TURN-серверы VK Звонков и Yandex Telemost. ISP видит обычный видеозвонок, а не VPN. Двухслойная обфускация: DTLS-шифрование + TURN-реле через легитимную инфраструктуру.

---

## Целевое состояние (Definition of Done)

Когда ВСЕ задачи плана выполнены, проект должен соответствовать этим критериям:

### Продукт
- Стабильный VPN-сервер с мониторингом, health check, graceful shutdown
- Десктоп-клиент (macOS/Linux/Windows) с автореконнектом
- Android-клиент с автореконнектом
- Веб-админка с HTTPS, статистикой клиентов, QR-кодами для конфигов
- Multi-link поддержка: failover между VK и Yandex TURN-серверами

### Качество кода
- 0 дублирования: VK/Yandex credentials, DTLS setup, packet pipe — в общих пакетах
- Тесты: покрытие серверных хэндлеров, клиентской логики, packet pipe (≥40 тестов)
- CI: автоматические тесты + линтер на каждый push/PR
- CI: сборка серверного бинарника + APK + публикация в Releases

### Безопасность
- DTLS certificate pinning (MITM-защита)
- Bcrypt для админского пароля
- Input validation на всех API-эндпоинтах
- Rate limiting на критических эндпоинтах

### Документация
- README.md с архитектурой, инструкциями деплоя, API-документацией

### Что НЕ входит в план (антискоуп)
- iOS-клиент — отдельный проект, здесь только заготовка архитектуры
- Kubernetes/оркестрация — overkill для single-server VPN
- Prometheus/Grafana — достаточно JSON-метрик в API
- Мультитенантность — один сервер = один оператор

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

### 1.1 README.md `[S]`
**Файл:** корень проекта
**Что сделать:**
- Описание проекта и принципа работы
- Архитектурная схема (ASCII или Mermaid)
- Инструкция по развёртыванию сервера (VPS, Ubuntu 24.04)
- Инструкция по подключению клиентов (macOS, Linux, Windows, Android)
- API-документация сервера (все эндпоинты)
- Требования: Go 1.25+, WireGuard, Ubuntu 24.04
**Готово когда:** README в корне, содержит все пункты выше, рендерится на GitHub

### 1.2 Валидация DTLS-сертификатов (Certificate Pinning) `[M]`
**Файлы:** `server/main.go`, `client/main.go`, `android/tunnel/tunnel.go`
**Проблема:** `InsecureSkipVerify: true` — MITM-атака тривиальна.
**Решение:**
- Сервер генерирует стабильный сертификат (сохраняется в `/etc/vkvpn/dtls-cert.pem`)
- Fingerprint сертификата включается в конфиг клиента
- Клиент проверяет fingerprint при DTLS-хэндшейке
- Добавить поле `dtls_fingerprint` в `/api/clients/appconfig`
**Зависимости:** нет
**Готово когда:** клиент отвергает соединение с неправильным fingerprint; тест на это

### 1.3 Graceful shutdown `[S]`
**Файл:** `server/main.go`
**Что сделать:**
- Обработка SIGTERM/SIGINT
- Закрытие DTLS-listener
- Сохранение конфигурации перед выходом
- Лог "shutting down gracefully"
**Зависимости:** нет
**Готово когда:** `kill PID` корректно завершает сервер, конфиг сохранён

### 1.4 Reconnect logic `[M]`
**Файлы:** `client/main.go`, `android/tunnel/tunnel.go`
**Проблема:** При обрыве TURN-соединения нет автоматического реконнекта.
**Решение:**
- Экспоненциальный backoff (1s, 2s, 4s, 8s, max 30s)
- Перезапрос credentials при ошибке авторизации
- Логирование попыток реконнекта
- Максимум попыток: настраиваемо (по умолчанию: бесконечно)
**Зависимости:** нет
**Готово когда:** при обрыве TURN клиент автоматически переподключается

---

## Приоритет 2 — Тестирование и CI

### 2.1 Тесты серверных API-хэндлеров `[M]`
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
**Зависимости:** нет (тестируем текущий код)
**Готово когда:** ≥15 тестов, `go test ./server/ -v` проходит

### 2.2 CI для Go-тестов + линтер `[S]`
**Файл:** создать `.github/workflows/test.yml` и `.golangci.yml`
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
**Линтеры:** `errcheck`, `govet`, `staticcheck`, `unused`, `gosimple`, `ineffassign`
**Зависимости:** 2.1 (должны быть тесты, чтобы CI имел смысл)
**Готово когда:** CI зелёный на PR, линтер не падает

### 2.3 Вынести дублированный код VK/Yandex credentials `[L]`
**Файлы:** `client/main.go`, `android/tunnel/tunnel.go`
**Проблема:** Код извлечения TURN-credentials дублируется в 2 местах — около 300 строк × 2.
**Решение:**
- Создать `pkg/turnauth/vk.go` и `pkg/turnauth/yandex.go`
- Единый интерфейс `GetCredentials(link string) (*TURNCredentials, error)`
- Для десктопного клиента: прямой импорт `pkg/turnauth`
- Для Android tunnel: gomobile не поддерживает слайсы структур и интерфейсы — нужен отдельный `pkg/turnauth/mobile.go` с плоскими функциями (`GetVkUsername(link) string`, `GetVkPassword(link) string` и т.д.)
- Покрыть тестами с mock HTTP (httptest.Server)
**Зависимости:** лучше ДО 2.4 (тесты клиента)
**Готово когда:** один source of truth для credentials, тесты на mock, оба клиента используют общий пакет

### 2.4 Тесты клиентского кода `[M]`
**Файл:** создать `client/main_test.go`
**Что покрыть:**
- DTLS-конфигурация (генерация сертификата)
- Формат TURN-запросов (mock HTTP) — если credentials вынесены в pkg/turnauth
- Packet forwarding логика
**Зависимости:** 2.3 (иначе тестируем код, который скоро переедет)
**Готово когда:** ≥8 тестов, `go test ./client/ -v` проходит

---

## Приоритет 3 — Надёжность и мониторинг

### 3.1 Health check эндпоинт `[S]`
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
**Зависимости:** нет
**Готово когда:** эндпоинт отвечает, тест в handlers_test.go

### 3.2 Метрики и статистика клиентов `[M]`
**Файлы:** `server/main.go`, `server/web/index.html`
**Что считать:**
- Количество активных DTLS-соединений (счётчик в bridge-функции)
- WireGuard-пиры online: парсинг `wg show wg0 latest-handshakes` + `wg show wg0 transfer`
- Uptime сервера
- Трафик per client (bytes sent/received)
**Отображение:**
- `GET /api/metrics` — JSON
- В админке: онлайн/оффлайн индикатор, трафик, последний handshake
**Зависимости:** нет
**Готово когда:** админка показывает онлайн-статус и трафик каждого клиента

### 3.3 Кэширование TURN-credentials `[S]`
**Файлы:** `pkg/turnauth/` (после рефакторинга) или `client/main.go`
**Проблема:** Каждое подключение запрашивает TURN-credentials заново (5 HTTP-запросов для VK).
**Решение:**
- Кэшировать credentials с TTL
- **ВАЖНО:** Сначала замерить реальный TTL credentials (поле `lifetime` в TURN Allocate response). НЕ гадать.
- При ошибке 401 — перезапрашивать
- Логировать время жизни credentials
**Зависимости:** 2.3 (рефакторинг credentials) — желательно, но не блокирует
**Готово когда:** повторные подключения не делают лишних HTTP-запросов в пределах TTL

---

## Приоритет 4 — Безопасность

### 4.1 Хэширование админского пароля `[S]`
**Файл:** `server/main.go`
**Проблема:** `AdminPass` хранится в plaintext в `/etc/vkvpn/config.json`.
**Решение:**
- Хранить bcrypt-хэш в поле `AdminPassHash`
- При первом запуске: сгенерировать пароль → вывести в stdout → сохранить хэш
- Обратная совместимость: если в конфиге есть старый `AdminPass` — мигрировать на хэш
- Сравнение через `bcrypt.CompareHashAndPassword`
**Зависимости:** нет
**Готово когда:** plaintext пароля нет в конфиге; старые конфиги автомигрируются

### 4.2 Input validation `[S]`
**Файл:** `server/main.go`
**Что валидировать:**
- Имя клиента: `^[a-zA-Z0-9_-]{1,64}$`
- TURN-ссылка: URL-формат, домен в allowlist (vk.com, telemost.yandex.ru)
- Размер тела запроса: `http.MaxBytesReader` ≤ 1MB
- Content-Type проверка
**Зависимости:** нет
**Готово когда:** невалидные запросы возвращают 400; тесты на граничные случаи

### 4.3 Генерация WireGuard-ключей без CLI `[S]`
**Файл:** `server/main.go`
**Проблема:** `wgGenKey()` вызывает `exec.Command("wg", "genkey")` — зависимость от внешнего бинарника.
**Решение:**
- `crypto/rand` + Curve25519 clamp + base64 (не нужна внешняя библиотека, 15 строк кода)
- Убрать зависимость от `wg` CLI для генерации ключей
**Зависимости:** нет
**Готово когда:** `wg` CLI не вызывается для keygen; тест генерации валидных ключей

### 4.4 HTTPS для веб-админки `[M]`
**Файл:** `server/main.go`
**Проблема:** Админка на HTTP :8080, пароль летит в открытом виде.
**Решение:**
- Флаг `-tls-cert` / `-tls-key` для своих сертификатов
- Если сертификаты не указаны — автогенерация самоподписанного
- **Опционально:** Let's Encrypt через `-domain` флаг (autocert)
**Зависимости:** нет
**Готово когда:** `https://SERVER_IP:8080` работает; без флагов — self-signed cert

### 4.5 Rate limiting на API `[S]`
**Файл:** `server/main.go`
**Что ограничить:**
- Неавторизованные запросы (неверный токен) — 10 req/min на IP
- Это единственная реальная угроза (брутфорс пароля)
**Реализация:** простой счётчик на `sync.Map` с TTL
**Зависимости:** нет
**Готово когда:** 11-й неавторизованный запрос с одного IP за минуту → 429

---

## Приоритет 5 — Функциональность

### 5.1 Multi-link поддержка `[L]`
**Файлы:** `server/main.go`, `server/web/index.html`, `client/main.go`, `android/tunnel/tunnel.go`
**Сейчас:** Сервер хранит один `ActiveLink` + `LinkType`.
**Цель:**
- Массив `Links[]` с приоритетами в конфиге сервера
- Клиент получает несколько ссылок в appconfig
- Failover: если одна ссылка не работает, пробовать следующую
- В админке: управление списком ссылок
**Зависимости:** 1.4 (reconnect logic)
**Готово когда:** при падении одного TURN-сервера клиент автоматически переключается на другой

### 5.2 QR-код для мобильного конфига `[S]`
**Файлы:** `server/web/index.html`
**Сейчас:** QR-код генерируется на клиенте (qrencode).
**Цель:** Генерация QR-кода в веб-админке через JS-библиотеку (qrcode.js, inline)
**Зависимости:** нет
**Готово когда:** кнопка "QR" рядом с клиентом, сканируется телефоном

### 5.4 iOS-клиент `[XL]` ⚠️ ОТДЕЛЬНЫЙ ПРОЕКТ
**Путь:** `ios/` (новая директория)
**Подход:**
- SwiftUI приложение
- wireguard-go через gomobile (как Android)
- Переиспользование `android/tunnel/tunnel.go` (или общий `pkg/tunnel/`)
- Network Extension для VPN
**Примечание:** Это не задача, а отдельный проект. В рамках текущего плана — только подготовка архитектуры (вынос tunnel.go в общий пакет, задача 2.3).

### 5.5 Автообновление клиентов `[M]`
**Файлы:** `server/main.go`, `client/main.go`
**Решение:**
- `GET /api/version` — текущая версия сервера
- Клиент при старте проверяет версию
- `GET /api/download/{platform}` — скачать обновлённый бинарник
- Self-update через замену бинарника
**Зависимости:** 6.2 (версионирование бинарников)
**Готово когда:** клиент сообщает о доступном обновлении

---

## Приоритет 6 — Инфраструктура

### 6.1 CI для серверного бинарника + версионирование `[M]`
**Файл:** создать `.github/workflows/build-server.yml`
**Содержание:**
- Триггер: push tag `v*`
- Сборка для linux/amd64 и linux/arm64
- `go build -ldflags "-X main.version=$TAG"` — версия из тега
- Загрузка в GitHub Releases
- Добавить `var version = "dev"` в `server/main.go` и `client/main.go`
**Зависимости:** нет
**Готово когда:** `git tag v2.1.0 && git push --tags` создаёт Release с бинарниками

### 6.2 Docker-контейнеризация сервера `[L]`
**Файл:** создать `Dockerfile` и `docker-compose.yml`
**Сложности:**
- WireGuard требует `--cap-add=NET_ADMIN`, `--device=/dev/net/tun`, `--sysctl net.ipv4.ip_forward=1`
- Нужен `network_mode: host` или сложная настройка iptables
- Вариант: WireGuard на хосте, в контейнере только DTLS-proxy + API
**Зависимости:** нет
**Готово когда:** `docker compose up` запускает рабочий VPN-сервер

### 6.3 Бэкап конфигурации `[S]`
**Файл:** `server/main.go`
**Что бэкапить:**
- `/etc/vkvpn/config.json` — клиенты, ключи
**Когда:** при каждом изменении конфига (добавление/удаление клиента)
**Куда:** `/etc/vkvpn/backups/config-{timestamp}.json`, ротация: последние 10
**Зависимости:** нет
**Готово когда:** после добавления клиента появляется бэкап

---

## Граф зависимостей

```
Размеры: [S] = часы, [M] = полдня-день, [L] = 2-3 дня, [XL] = неделя+

Независимые (можно начинать сразу):
  1.1 README [S]
  1.2 DTLS cert pinning [M]
  1.3 Graceful shutdown [S]
  1.4 Reconnect logic [M]
  2.1 Тесты хэндлеров [M]
  3.1 Health check [S]
  4.1 Bcrypt пароль [S]
  4.2 Input validation [S]
  4.3 WG keygen без CLI [S]
  5.2 QR-коды [S]
  6.1 CI + версионирование [M]
  6.3 Бэкапы [S]

Цепочки:
  2.1 → 2.2 CI (нужны тесты для CI)
  2.3 Рефакторинг credentials [L] → 2.4 Тесты клиента [M]
  2.3 → 3.3 Кэширование credentials [S]
  1.4 Reconnect → 5.1 Multi-link [L]
  3.2 Метрики [M] (используется в 3.1 health check, но можно делать параллельно)
  6.1 Версионирование → 5.5 Автообновление [M]
  4.4 HTTPS [M] — независим, но лучше после 4.1 (bcrypt)

Рекомендуемый порядок (параллельные потоки):
  Поток A (безопасность): 4.1 → 4.2 → 4.3 → 1.2 → 4.4
  Поток B (тесты/CI):     2.1 → 2.2 → 2.3 → 2.4
  Поток C (надёжность):   1.3 → 3.1 → 3.2 → 1.4 → 5.1
  Поток D (инфраструктура): 1.1 → 6.1 → 6.3
```

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

## Порядок работы для агентов

1. **Прочитай этот файл** целиком перед началом работы
2. **Прочитай CLAUDE.md** если есть — там могут быть дополнительные инструкции
3. **Ветка разработки:** создавай ветку по задаче (`claude/<task-name>`) от `main`
4. **Коммитить** после каждого логического шага, не копить изменения
5. **Тесты:** запускай `go test ./server/ ./pkg/... -v` перед коммитом
6. **Не трогай** `releases/` — бинарники обновляются вручную
7. **Не ломай** существующий API — обратная совместимость важна
8. **PR:** создавай PR в `main` после завершения задачи

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
