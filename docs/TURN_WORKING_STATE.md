# TURN Protocol — Working State Reference

> **ВАЖНО**: TURN протокол РАБОТАЕТ (подтверждено 01.04.2026). Любые изменения в проекте
> ДОЛЖНЫ сверяться с этим документом, чтобы не сломать рабочую конфигурацию.

## Текущая архитектура (апрель 2026)

```
Android App                        VPS (144.124.247.27)
    │                                    │
    │  1. GET /api/turn-creds?name=X     │
    │ ──────────────────────────────────► │ → calls.start (VK API) → свежие TURN creds
    │  ◄──────────────────────────────── │
    │  {turn_username, turn_password,    │
    │   turn_address}                    │
    │                                    │
    │  2. TURN allocation                │
    │ ──► VK TURN relay (155.x.x.x) ──► │ DTLS (port 56000)
    │                                    │
    │  3. DTLS tunnel                    │
    │ ◄════════════════════════════════► │ → WireGuard (port 51820)
    │                                    │
    │  4. Internet traffic               │
    │ ◄══════════════════════════════════╡ → NAT → Internet
```

### Поток данных

1. **Android при каждом подключении** запрашивает свежие TURN credentials:
   - `SetServerInfo(serverURL, clientName)` → сохраняет URL и имя клиента
   - `fetchFreshCreds()` → `GET /api/turn-creds?name=X` → обновляет `serverTurnCreds`
   - Вызывается в начале `Start()` и при реконнекте в `oneTurnConnectionLoop()`

2. **Сервер** отдаёт credentials через `/api/turn-creds` (без авторизации):
   - Если есть активный звонок в `credPool` → возвращает текущие credentials
   - Если нет → `runSchedulerTick()` → `startCallForAccount()` → `calls.start` (VK API)
   - VK API цепочка: `calls.start` → `get_anonym_token` → `getAnonymousToken` → `anonymLogin` → `joinConversationByLink` → TURN creds

3. **VPS** принимает DTLS connections:
   - `runDTLSServer()` слушает на порту 56000
   - `sessionmux` группирует DTLS connections по session ID (16-byte UUID)
   - Каждая сессия имеет один UDP socket к WireGuard (51820)

### Ключевые параметры

| Параметр | Значение | Где задаётся |
|----------|----------|--------------|
| DTLS port | 56000/udp | `server/main.go` flag `-dtls-addr` |
| WG port | 51820/udp | `/etc/vkvpn/config.json` `wg_port` |
| WG MTU | 1000 | `server/main.go` `applyWireGuard()` |
| DTLS cipher | TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 | Клиент и сервер |
| DTLS CID (server) | RandomCIDGenerator(8) | `server/main.go` |
| DTLS CID (client) | OnlySendCIDGenerator() | `android/tunnel/tunnel.go` |
| Extended Master Secret | Required | Обе стороны |
| Session handshake | 0x00 + 16-byte UUID | Первый пакет после DTLS handshake |
| TURN connections | 2 (server-provided creds) | `android/tunnel/tunnel.go` |
| WG keepalive | 25 секунд | IPC config `persistent_keepalive_interval` |
| Call duration | 23 часа | `server/main.go` `startCallForAccount()` |

### Критические файлы

```
server/main.go                    — DTLS сервер, /api/turn-creds, credential pool, call scheduler
android/tunnel/tunnel.go          — DTLS+TURN клиент, fetchFreshCreds(), WireGuard bridge
android/app/.../TunnelVpnService.kt — SetServerInfo() вызов, передача client_name
android/app/.../MainActivity.kt   — putExtra("client_name", ...) в intent
pkg/turnauth/vk.go                — VK API для получения TURN credentials
pkg/sessionmux/sessionmux.go      — Мультиплексор DTLS сессий
```

### Runtime Credential Refresh (ключевая фича)

**Проблема**: VK убивает звонок через несколько минут после `calls.start` если никто не подключён через WebRTC. После этого TURN allocation мертва.

**Решение**: Android запрашивает свежие credentials при каждом подключении:

```
Android                                Server
   │                                      │
   │ SetServerInfo(url, name)             │
   │ Start() → fetchFreshCreds()          │
   │ GET /api/turn-creds?name=Alex ─────► │
   │                                      │ credPool.GetOrAssignCreds("Alex")
   │                                      │ (или startCallForAccount() если нет активного)
   │ ◄──── {user, pass, addr} ─────────── │
   │                                      │
   │ serverTurnCreds = fresh creds        │
   │ oneTurnConnection() → allocate OK    │
   │                                      │
   │ ... TURN allocation умирает ...      │
   │                                      │
   │ oneTurnConnectionLoop() retry:       │
   │ fetchFreshCreds() ──────────────────►│ (новый calls.start если нужно)
   │ ◄──── {user, pass, addr} ─────────── │
   │ oneTurnConnection() → allocate OK    │
```

**Важно для конфига**: При импорте конфига в приложение (`/api/clients/appconfig`) поле `name` должно присутствовать — оно сохраняется как `client_name` и передаётся в `SetServerInfo()`.

### VK Account Pool

- Аккаунты хранятся в `config.json` → `vk_accounts[]`
- Scheduler (`startCallScheduler`) каждые 30 секунд проверяет
- Call duration = 23 часа (максимум, пока credentials валидны)
- При expire → сразу `idle` (без cooldown) → новый звонок
- Статусы: `idle` → `calling` → (23ч) → `idle` (цикл)
- Ошибки: `rate_limited` (30 мин пауза), `token_expired`, `banned`
- **VK OAuth токен живёт ~24ч** — нужен refresh или новый OAuth до истечения

### Фиксы, которые сделали TURN рабочим

1. **Runtime credential refresh** (главный фикс):
   - **Было**: credentials импортировались один раз при сканировании QR, протухали через минуты
   - **Стало**: `fetchFreshCreds()` дёргает `/api/turn-creds` при каждом подключении и реконнекте
   - **Файлы**: `android/tunnel/tunnel.go`, `server/main.go`

2. **Каскадный сбой DTLS connections**:
   - **Было**: `context.AfterFunc` ставил `listenConn.SetDeadline(now)` на SHARED UDP socket → все connections умирали
   - **Стало**: deadline только на `dtlsConn`, сброс `listenConn.SetDeadline(time.Time{})` при реконнекте
   - **Файл**: `android/tunnel/tunnel.go` → `oneDtlsConnection()`

3. **Уменьшение параллельных connections** (8 → 2):
   - 2 connections: один активный + один hot standby

4. **Call duration 23ч** (вместо 1-3ч):
   - Scheduler не ротирует звонки без необходимости
   - Нет cooldown при expire

5. **WG MTU = 1000**:
   - Необходимо для VP8 transport (MaxPayloadSize=1100, WG overhead=48)
   - TURN не ограничен по размеру пакетов

### Что НЕЛЬЗЯ менять без проверки

- **`/api/turn-creds` endpoint**: без авторизации, принимает `?name=X`, возвращает 3 поля
- **`fetchFreshCreds()`**: вызывается в `Start()` и `oneTurnConnectionLoop()` — убрать = сломать
- **`SetServerInfo()`**: вызывается из `TunnelVpnService.kt` — без него `fetchFreshCreds()` не работает
- **`client_name` в intent**: `MainActivity.kt` передаёт, `TunnelVpnService.kt` читает
- **DTLS конфиг**: cipher suite, CID generator, ExtendedMasterSecret — совпадение клиент/сервер
- **Session handshake**: формат `0x00 + 16 bytes UUID`
- **`listenConn`**: shared UDP socket — НЕ ставить deadline из per-connection контекста
- **WG MTU ≤ 1052**: иначе VP8 сломается
- **DTLS port 56000**: зашит в конфиги клиентов

### Тест на работоспособность

```bash
# 1. Проверить endpoint (должен вернуть JSON с credentials)
curl -sk https://144.124.247.27:8080/api/turn-creds?name=Alex

# 2. Проверить WireGuard peers на VPS
ssh root@144.124.247.27 'wg show'
# Должен быть peer с recent handshake и transfer > 0

# 3. Проверить DTLS
ssh root@144.124.247.27 'ss -ulnp | grep 56000'

# 4. Проверить VK аккаунт
# В admin панели: статус "calling", TURN CREDS: OK

# 5. Проверить логи
ssh root@144.124.247.27 'journalctl -u vkvpn -n 20 --no-pager | grep -v "TLS handshake"'
```
