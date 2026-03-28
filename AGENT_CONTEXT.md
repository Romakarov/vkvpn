# AGENT_CONTEXT.md — Контекст для будущих агентов

> **ВНИМАНИЕ:** В этом виде система работает (проверено 2026-03-28). Не ломай то, что работает!

## Оригинальные репозитории
- **Desktop клиент/сервер:** https://github.com/cacggghp/vk-turn-proxy
- **Android клиент:** https://github.com/MYSOREZ/vk-turn-proxy-android

## Текущее состояние: ВСЁ РАБОТАЕТ

VPN-туннель через TURN-серверы VK работает. Клиент на Android подключается, интернет идёт.

### Что работает
- Сервер на VPS `144.124.247.27` — `systemctl status vkvpn`
- WireGuard на порту 51820/udp
- DTLS listener на порту 56000/udp
- Админка на порту 8080/tcp (HTTPS, self-signed cert)
- Android клиент подключается через TURN → DTLS → WireGuard
- VK OAuth токен используется для получения TURN credentials на сервере
- Credentials автоматически обновляются каждые 5 минут

---

## Архитектура туннеля

```
Android                          VPS (144.124.247.27)
┌──────────┐                     ┌──────────────────┐
│ TUN iface│──WG encrypt──►      │                  │
│          │   │                  │  WireGuard :51820│──► Интернет
│ DTLS     │◄─►│ TURN relay ◄───►│  DTLS     :56000 │
│ client   │   │ (VK servers)    │  HTTP API :8080  │
└──────────┘                     └──────────────────┘
```

Трафик: `Приложение → TUN → WireGuard → DTLS → TURN (VK) → VPS → WireGuard → Интернет`

ISP видит только TURN-трафик (как обычный VK-звонок).

---

## Критические настройки VPS

### Порты (НЕ МЕНЯТЬ!)
| Порт | Протокол | Назначение |
|------|----------|------------|
| 51820 | UDP | WireGuard — ОБЯЗАТЕЛЬНО этот порт, захардкожен в клиентах |
| 56000 | UDP | DTLS listener |
| 8080 | TCP | Админка (HTTPS) |
| 3128 | TCP | Squid proxy (для OAuth через российский IP) |

### Файлы на VPS
| Путь | Что это |
|------|---------|
| `/opt/vkvpn/server` | Бинарник сервера |
| `/etc/vkvpn/config.json` | Конфиг (ключи, клиенты, VK аккаунты, пароль) |
| `/etc/vkvpn/dtls-cert.pem` | DTLS сертификат (фингерпринт отдаётся клиентам!) |
| `/etc/vkvpn/dtls-key.pem` | DTLS приватный ключ |
| `/etc/vkvpn/web-cert.pem` | TLS сертификат для HTTPS админки |
| `/etc/wireguard/wg0.conf` | WireGuard конфиг (пиры синхронизируются автоматически) |

### Systemd сервис
```bash
systemctl status vkvpn    # статус
systemctl restart vkvpn   # перезапуск
journalctl -u vkvpn -f    # логи в реальном времени
```

### WireGuard
```bash
wg show wg0               # статус пиров
wg-quick down wg0 && wg-quick up wg0   # полный перезапуск
wg syncconf wg0 <(wg-quick strip wg0)  # горячая перезагрузка конфига
```

### Текущий конфиг
- **Подсеть:** `10.66.66.0/24`, сервер `10.66.66.1`
- **DNS:** `1.1.1.1, 8.8.8.8`
- **Админ-пароль (bcrypt hash):** хранится в `config.json` → `admin_pass_hash`
- **Токен для входа в админку:** `4BRxevX2HIAXyW_E`

---

## VK OAuth и TURN credentials

### Как работает (текущая рабочая схема)
1. На сервере хранится VK `access_token` (раздел `vk_accounts` в config.json)
2. Каждые 5 минут сервер вызывает `calls.start` с этим токеном
3. Из ответа извлекаются TURN credentials (username, password, address)
4. Credentials отдаются клиентам через `/api/clients/appconfig`
5. Клиент использует эти credentials для подключения к TURN relay

### Токен живёт 24 часа!
- `expires_in=86400` — через сутки токен протухнет
- Нужно обновлять вручную через OAuth:
  1. Поднять Squid proxy на VPS (порт 3128) — если не запущен
  2. Настроить FoxyProxy в Chrome → HTTP proxy → `144.124.247.27:3128`
  3. Открыть: `https://oauth.vk.com/authorize?client_id=6287487&scope=audio,video,offline&response_type=token&v=5.264&redirect_uri=https://oauth.vk.com/blank.html`
  4. Залогиниться в VK
  5. Скопировать `access_token` из URL после редиректа на blank.html
  6. Вставить в админке → VK Accounts → Manual token entry

### Squid proxy на VPS
Нужен для OAuth (VK доступен через российский VPS). **НЕ УДАЛЯТЬ!**
```bash
# Установка (если удалён)
apt-get install -y squid
cat > /etc/squid/squid.conf << 'EOF'
http_port 3128
acl SSL_ports port 443
acl Safe_ports port 80
acl Safe_ports port 443
acl CONNECT method CONNECT
http_access allow CONNECT SSL_ports
http_access allow all
EOF
systemctl restart squid

# Файрвол
ufw allow 3128/tcp
iptables -I INPUT -p tcp --dport 3128 -j ACCEPT
```

### FoxyProxy настройка в Chrome
1. Установить расширение FoxyProxy из Chrome Web Store
2. Proxies → Add → Title: `VPS`, Type: `HTTP`, Hostname: `144.124.247.27`, Port: `3128`
3. Username и Password — ПУСТЫЕ
4. Save, включить proxy, открыть OAuth ссылку

### Ссылка на VK-звонок (TURN Links) — БОЛЬШЕ НЕ НУЖНА
Раньше использовалась для анонимного получения TURN credentials. Сейчас credentials берутся через OAuth токен. Ссылку можно не добавлять.

---

## Android клиент

### Сборка APK
```bash
# На Mac с установленным Android SDK и NDK
cd /Users/roman/VKvpnn

# 1. Собрать tunnel.aar (Go → Android library)
gomobile bind -target=android -androidapi=21 -o android/app/libs/tunnel.aar ./android/tunnel/

# 2. Собрать APK
cd android && ./gradlew assembleDebug
cp app/build/outputs/apk/debug/app-debug.apk ../releases/vkvpn-debug.apk
```

### Конфиг клиента (appconfig)
Клиент получает JSON через QR-код из админки:
```json
{
  "name": "client_name",
  "server": "144.124.247.27",
  "dtls_port": 56000,
  "dtls_fingerprint": "sha256_hex_of_dtls_cert",
  "wg_address": "10.66.66.2",
  "wg_port": 51820,
  "wg_privkey": "client_private_key",
  "wg_pubkey": "server_public_key",
  "wg_dns": "1.1.1.1, 8.8.8.8",
  "creds_mode": "server",
  "turn_username": "...",
  "turn_password": "...",
  "turn_address": "host:port"
}
```

Когда `creds_mode=server` — клиент использует `turn_*` поля напрямую, без своего OAuth.

### Подключение клиента
1. Открыть админку → выбрать клиента → QR / Config → VKVPN App (Android)
2. В приложении: Scan QR → Connect
3. Проверить: `wg show wg0` на VPS должен показать handshake и transfer

---

## Что НЕ ТРОГАТЬ (хрупкие места)

### 1. DTLS сертификат
Фингерпринт `dtls-cert.pem` захардкожен в конфигах всех клиентов. Если пересоздать сертификат — ВСЕ клиенты перестанут подключаться. Нужно будет пересканировать QR.

### 2. WireGuard порт 51820
Захардкожен в `wg0.conf` и в клиентских конфигах. НЕ МЕНЯТЬ.

### 3. Server public key
`psEb6d8fVyrXpTgSZMscFLJL//kyjircfQ9RJmlI6GM=` — отдаётся клиентам. Если пересоздать — все клиенты сломаются.

### 4. Rate limiter
Настроен на 100 неудачных попыток в минуту. Считает ТОЛЬКО реально неверные пароли (не пустые запросы). Если вернуть старое поведение — админка будет блокироваться от собственных AJAX-запросов.

### 5. wg syncconf после добавления клиента
Сервер пишет в wg0.conf и должен вызвать `wg syncconf`. Если этого не происходит — новые клиенты не смогут подключиться (WG не знает о них). Проверяй `wg show wg0` — должны быть ВСЕ пиры из config.json.

### 6. Один DTLS коннект на клиента
Клиент должен открывать РОВНО ОДИН DTLS коннект. Если несколько — WG путается в endpoint'ах и handshake не проходит.

### 7. Squid proxy
**НЕ УДАЛЯТЬ!** Нужен для обновления VK токена через браузер пользователя.

---

## Деплой сервера

```bash
# Из корня проекта на Mac:
GOOS=linux GOARCH=amd64 go build -ldflags '-s -w' -trimpath -o /tmp/vkvpn-server ./server/
scp /tmp/vkvpn-server root@144.124.247.27:/opt/vkvpn/server
ssh root@144.124.247.27 'chmod +x /opt/vkvpn/server && systemctl restart vkvpn'

# Или через deploy.sh:
./deploy.sh root@144.124.247.27
```

### После деплоя ОБЯЗАТЕЛЬНО проверить:
```bash
ssh root@144.124.247.27 '
  systemctl is-active vkvpn &&
  wg show wg0 | grep "listening port" &&
  curl -sk https://localhost:8080/api/status?token=4BRxevX2HIAXyW_E | python3 -m json.tool
'
```
Ожидаемый результат: сервис active, порт 51820, JSON со статусом.

---

## Тесты

```bash
go test ./server/ ./pkg/... -v -race
```

Все тесты должны проходить перед коммитом.

---

## Частые проблемы и решения

### "No TURN credentials" / "no active TURN link"
**Причина:** VK токен протух (24 часа).
**Решение:** Обновить токен через OAuth (см. раздел VK OAuth выше).

### WG handshake не проходит
**Причина 1:** WG слушает на неправильном порту (после syncconf).
**Проверка:** `wg show wg0 | grep "listening port"` — должен быть 51820.
**Решение:** `wg-quick down wg0 && wg-quick up wg0`

**Причина 2:** Пир не добавлен в WG.
**Проверка:** `wg show wg0` — должны быть все пиры из config.json.
**Решение:** `wg syncconf wg0 <(wg-quick strip wg0)`

### "connection refused" на 127.0.0.1:51820
**Причина:** WG interface упал или слушает на другом порту.
**Решение:** `wg-quick down wg0 && wg-quick up wg0`

### 10+ DTLS коннектов одновременно
**Причина:** Старая версия клиента (до фикса single-connection).
**Решение:** Пересобрать APK с актуальным tunnel.go.

### Rate limit (too many requests) в админке
**Причина:** Старый код считал все запросы без auth как failures.
**Решение:** В текущей версии исправлено — считаются только запросы с неверным токеном.

### Squid proxy не работает
**Проверка:** `systemctl status squid`, `curl -x http://127.0.0.1:3128 -s -o /dev/null -w "%{http_code}" https://vk.com/`
**Решение:** Переустановить (см. раздел Squid выше).

---

## Доступы

| Ресурс | Данные |
|--------|--------|
| VPS SSH | `root@144.124.247.27`, пароль: `6M:zH3WFT7U25Tg21chX` |
| Админка | `https://144.124.247.27:8080/?token=4BRxevX2HIAXyW_E` |
| GitHub | `https://github.com/Romakarov/vkvpn` |
| VK аккаунт | user_id: 886137412, телефон: +7 936 314 5672 |

---

## Git

- **Основная ветка:** `main`
- **Рабочие ветки:** `claude/<task-name>` от `main`
- **APK:** `releases/vkvpn-debug.apk` — коммитится в репо для удобства скачивания
- **Правило:** PR в main после завершения задачи

---

## Резюме для агента

1. **Не трогай** DTLS cert, WG порт, server keys, rate limiter логику, Squid proxy
2. **Перед деплоем** — прогони тесты: `go test ./server/ ./pkg/... -v -race`
3. **После деплоя** — проверь WG порт (`51820`) и статус сервиса
4. **Токен VK** протухает через 24ч — нужен Squid proxy + FoxyProxy для обновления
5. **Один DTLS коннект** на клиента — не меняй эту логику
6. **wg syncconf** должен вызываться после добавления/удаления клиентов
7. **Перед тем как что-то удалять на VPS** — подумай дважды, оно может быть нужно
