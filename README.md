# VKVPN

VPN-система, туннелирующая WireGuard через TURN-серверы VK Звонков и Yandex Telemost. ISP видит обычный видеозвонок, а не VPN. Двухслойная обфускация: DTLS + TURN-реле.

## Архитектура

```
[Устройство] <-- WireGuard --> [Локальный UDP :9000]
                                       |
                                 [DTLS клиент]
                                       |
                           [TURN-реле VK/Yandex]
                                       |
                                 [VPS :56000]
                                       |
                                 [DTLS сервер]
                                       |
                           [WireGuard :51820] --> Интернет
```

ISP видит только трафик до TURN-серверов VK/Yandex (легитимные IP для видеозвонков). Сам трафик зашифрован DTLS 1.2. Внутри DTLS — WireGuard-пакеты. Двойное шифрование.

## Быстрый старт

### Требования

- **VPS**: Ubuntu 24.04, 1 CPU / 1 GB RAM
- **Go**: 1.25+
- **WireGuard**: установлен на VPS

### Установка сервера

```bash
# 1. Клонировать репо
git clone https://github.com/Romakarov/vkvpn.git
cd vkvpn

# 2. Деплой на VPS (сборка + загрузка + установка)
./deploy.sh root@YOUR_VPS_IP

# Или вручную:
GOOS=linux GOARCH=amd64 go build -ldflags '-s -w' -trimpath -o vkvpn-server ./server/
scp vkvpn-server install.sh root@YOUR_VPS_IP:/tmp/
ssh root@YOUR_VPS_IP 'bash /tmp/install.sh'
```

### Настройка

1. Откройте админку: `http://YOUR_VPS_IP:8080/?token=YOUR_PASSWORD`
2. Добавьте TURN-ссылку (VK Call или Yandex Telemost)
3. Создайте клиента
4. Скачайте WireGuard-конфиг или отсканируйте QR-код

### Подключение клиента (Desktop)

```bash
# Собрать клиент
go build -o vkvpn-client ./client/

# Запустить (VK)
./vkvpn-client -vk-link "https://vk.com/call/join/HASH" -peer YOUR_VPS_IP:56000

# Запустить (Yandex Telemost)
./vkvpn-client -yandex-link "https://telemost.yandex.ru/j/ID" -peer YOUR_VPS_IP:56000

# Поднять WireGuard
sudo wg-quick up ./client.conf
```

### Подключение клиента (Android)

1. Установите APK из [Releases](https://github.com/Romakarov/vkvpn/releases)
2. Отсканируйте QR-код конфига из админки (вкладка "VKVPN App")
3. Нажмите "Connect"

### HTTPS для админки

```bash
# С автогенерацией самоподписанного сертификата
./vkvpn-server --auto-tls

# Со своими сертификатами
./vkvpn-server --tls-cert /path/to/cert.pem --tls-key /path/to/key.pem
```

## API сервера

Все эндпоинты (кроме отмеченных) требуют авторизации: `?token=PASSWORD`, cookie `admin_token`, или заголовок `X-Admin-Token`.

| Метод | Путь | Описание |
|-------|------|----------|
| GET | `/api/health` | Статус сервера (без авторизации) |
| GET | `/api/status` | Информация о сервере |
| GET | `/api/metrics` | Метрики: трафик, онлайн-статус клиентов |
| POST | `/api/link` | Добавить TURN-ссылку (`{"link":"...","type":"vk\|yandex"}`) |
| POST | `/api/link/delete` | Удалить ссылку (`{"url":"..."}`) |
| GET | `/api/link/active` | Текущая активная ссылка (без авторизации, для клиентов) |
| GET | `/api/clients` | Список клиентов |
| POST | `/api/clients/add` | Создать клиента (`{"name":"..."}`) |
| POST | `/api/clients/delete` | Удалить клиента (`{"name":"..."}`) |
| POST | `/api/clients/toggle` | Включить/выключить клиента (`{"name":"..."}`) |
| GET | `/api/clients/config?name=X` | WireGuard-конфиг клиента |
| GET | `/api/clients/appconfig?name=X` | JSON-конфиг для Android |
| GET | `/api/logs` | Логи сервера |

## Структура проекта

```
server/main.go              — Сервер: HTTP API + DTLS listener + WireGuard
client/main.go              — Десктоп-клиент: TURN + DTLS туннель
android/tunnel/tunnel.go    — Android-клиент (gomobile binding)
android/app/src/            — Android UI (Kotlin)
pkg/packetpipe/             — Пакетный пайп (общий)
pkg/turnauth/               — VK/Yandex credential extraction (общий)
server/web/index.html       — Веб-админка
deploy.sh                   — Деплой на VPS
install.sh                  — Установка на VPS с нуля
.github/workflows/          — CI: тесты, сборка APK, релизы
```

## Безопасность

- **DTLS Certificate Pinning**: сервер генерирует стабильный сертификат, клиент проверяет SHA-256 fingerprint
- **Bcrypt**: админский пароль хранится в виде bcrypt-хэша
- **Rate Limiting**: 10 неуспешных попыток авторизации в минуту → 429
- **Input Validation**: имена клиентов, размер запросов, формат данных
- **Config Backups**: автоматический бэкап при каждом изменении

## Сборка и тесты

```bash
# Тесты
go test ./server/ ./pkg/... -v -race

# Сборка
go build -ldflags '-s -w' -trimpath -o vkvpn-server ./server/
go build -ldflags '-s -w' -trimpath -o vkvpn-client ./client/

# Линтер
go vet ./...
```

## Порты

| Порт | Протокол | Описание |
|------|----------|----------|
| 51820 | UDP | WireGuard |
| 56000 | UDP | DTLS listener |
| 8080 | TCP | Админка (HTTP/HTTPS) |

## Лицензия

GPL-3.0
