# Контекст для будущих агентов

## Оригинальные репозитории
- **Desktop клиент/сервер:** https://github.com/cacggghp/vk-turn-proxy
- **Android клиент:** https://github.com/MYSOREZ/vk-turn-proxy-android
- **Видео с демо:** https://youtu.be/hJmg3GLfFUo?si=CWjHgoajBtDC_KLl

## Текущий статус (27 марта 2026)

### VK TURN
- `client_id=6287487` захардкожен в оригинале и во всех форках — **один на всех пользователей по миру**
- 27 марта 2026 VK начал возвращать `error_code: 29` (Rate limit reached) на метод `calls.getAnonymousAccessTokenPayload`
- В issue https://github.com/cacggghp/vk-turn-proxy/issues/48 обсуждают что VK мог закрыть анонимный доступ к звонкам
- Issue https://github.com/cacggghp/vk-turn-proxy/issues/39 (закрыта 26 марта) — "Call requires auth" решалась включением тумблера "анонимные подключения" при создании звонка
- **Неясно:** это временный rate limit или VK закрыл API навсегда. Нужно проверить позже.

### Яндекс Telemost TURN
- TURN credentials получаются успешно (через WebSocket handshake)
- TURN Allocate проходит — relay address выдаётся
- **НО: `CreatePermission` возвращает `error 403: Forbidden IP`** — Яндекс TURN не позволяет relay на произвольные внешние IP
- **Оригинальный клиент тоже не работает с Яндексом** — протестировано на VPS, та же ошибка 403
- Яндекс TURN работает только между участниками звонка через ICE, не как open relay

### Что работает
- Сервер на VPS: DTLS listener, WireGuard, админка, device logs API
- Android приложение: QR-сканер, шифрованное хранилище, логирование с отправкой на VPS, просмотр логов
- Код туннеля: TURN connect, allocate — всё проходит. Проблема на уровне TURN relay (VK rate limit / Yandex 403)

## Реализовано (27 марта 2026, вечер)

### Серверная VK OAuth авторизация
Реализован вариант 2 — серверная авторизация через VK-аккаунт:
- Сервер авторизуется в VK через OAuth, хранит access_token
- Фоновый процесс каждые 5 минут извлекает TURN credentials через `GetVKCredentialsWithToken`
- Credentials кэшируются и отдаются клиентам через `/api/clients/appconfig` (поля `turn_username`, `turn_password`, `turn_address`)
- Клиенты (Android, desktop) используют серверные credentials напрямую, пропуская сломанный VK anonymous flow
- Админка: секция "VK Accounts" для управления OAuth-аккаунтами

**Новые API эндпоинты:**
- `GET /api/vk/auth-url` — OAuth URL для авторизации
- `GET /api/vk/callback` — OAuth callback от VK
- `GET /api/vk/accounts` — список VK аккаунтов
- `POST /api/vk/accounts/delete` — удалить аккаунт
- `GET /api/vk/credentials` — статус кэшированных credentials
- `POST /api/vk/credentials/refresh` — принудительное обновление

**Статус:** задеплоено на VPS, сервер работает. Нужно авторизовать VK-аккаунт через админку для проверки полного flow.

## Что нужно сделать

### Приоритет 1: Проверить VK OAuth flow
- Зайти в админку https://144.124.247.27:8080/?token=4BRxevX2HIAXyW_E
- Нажать "Add VK Account" → авторизоваться в VK
- Проверить что TURN credentials появляются
- Если client_id 6287487 не работает с OAuth — зарегистрировать своё приложение на vk.com/dev

### Приоритет 2: Яндекс TURN
- Яндекс TURN не работает как open relay (403 Forbidden IP)
- Возможно нужен другой подход: ICE negotiation через WebSocket, как настоящий WebRTC peer
- Или Яндекс для этого проекта непригоден

## VPS доступ
- IP: 144.124.247.27
- SSH: root / 6M:zH3WFT7U25Tg21chX
- Админка: https://144.124.247.27:8080/?token=4BRxevX2HIAXyW_E
- Device logs: GET /api/device-logs (с авторизацией)
- Сервис: systemctl status vkvpn
- Конфиг: /etc/vkvpn/config.json
