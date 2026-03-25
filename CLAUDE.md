# VKVPN — Инструкции для Claude Code

## Что это
VPN-система на Go: WireGuard-трафик туннелируется через TURN-серверы VK/Yandex. Двухслойная обфускация: DTLS + TURN-реле.

## Сборка и тесты

```bash
# Тесты (ОБЯЗАТЕЛЬНО перед каждым коммитом)
go test ./server/ ./pkg/... -v -race

# Сборка сервера
go build -ldflags '-s -w' -trimpath -o /tmp/vkvpn-server ./server/

# Сборка клиента
go build -ldflags '-s -w' -trimpath -o /tmp/vkvpn-client ./client/

# Линтер
go vet ./...
```

## Структура проекта

```
server/main.go              — Сервер: HTTP API + DTLS listener + WireGuard управление
client/main.go              — Десктоп-клиент: TURN + DTLS tunnel
android/tunnel/tunnel.go    — Android-клиент (gomobile binding)
android/app/src/            — Android UI (Kotlin)
pkg/packetpipe/             — Общий пакет пересылки пакетов
server/web/index.html       — Веб-админка (встроенная)
deploy.sh                   — Деплой на VPS: сборка + scp + рестарт
install.sh                  — Установка на VPS с нуля (Ubuntu 24.04)
scripts/connect-mac.sh      — Клиент-скрипт для Mac/Linux
scripts/connect-win.bat     — Клиент-скрипт для Windows
.github/workflows/          — CI: сборка APK
```

## Правила работы

1. **Читай PROJECT_PLAN.md** — там полный план с приоритетами и зависимостями
2. **Ветка:** `claude/<task-name>` от `main`
3. **Коммитить** после каждого логического шага
4. **Тесты перед коммитом:** `go test ./server/ ./pkg/... -v -race`
5. **Не трогай `releases/`** — бинарники обновляются вручную
6. **Обратная совместимость API** — не ломай существующие эндпоинты
7. **PR в `main`** после завершения задачи

## API сервера (ключевые эндпоинты)

- `GET /api/status` — статус сервера + список клиентов (авторизация: `?token=PASS`)
- `POST /api/clients/add` — добавить клиента (`name`)
- `POST /api/clients/delete` — удалить клиента (`name`)
- `POST /api/clients/toggle` — вкл/выкл клиента (`name`)
- `GET /api/clients/config?name=X` — WireGuard конфиг клиента
- `GET /api/clients/appconfig?name=X` — JSON конфиг для Android-клиента
- `POST /api/link` — установить TURN-ссылку (`link`, `type`)

## Деплой на VPS

```bash
# Полная установка с нуля
./deploy.sh root@<VPS_IP>

# Что делает deploy.sh:
# 1. Кросс-компилирует сервер (linux/amd64)
# 2. scp бинарник + install.sh на VPS
# 3. install.sh ставит WireGuard, создаёт конфиг, systemd-сервис
# 4. systemctl restart vkvpn
```

### Пути на VPS
- `/opt/vkvpn/server` — бинарник сервера
- `/etc/vkvpn/config.json` — конфигурация (ключи, клиенты, пароль)
- `/etc/wireguard/wg0.conf` — конфиг WireGuard
- Сервис: `systemctl status vkvpn`
- Порты: 51820/udp (WG), 56000/udp (DTLS), 8080/tcp (админка)

## Зависимости

- Go 1.25+
- pion/dtls, pion/turn — DTLS и TURN протоколы
- gorilla/websocket — для Yandex
- На VPS: WireGuard, Ubuntu 24.04

## Автономная работа

При команде "работай по плану":
1. Прочитай `PROJECT_PLAN.md` — найди задачу с наивысшим приоритетом без зависимостей
2. Создай ветку `claude/<task-name>`
3. Реализуй задачу по критериям "Готово когда" из плана
4. Прогони тесты
5. Создай PR в `main`
6. Переходи к следующей задаче
