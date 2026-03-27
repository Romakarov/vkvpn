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

## Что нужно сделать

### Приоритет 1: Починить доступ к VK TURN
Варианты:
1. **Свой `client_id`** — зарегистрировать VK-приложение на vk.com/dev, получить свой client_id/secret. Непонятно — даст ли VK доступ к `calls.getAnonymousAccessTokenPayload`
2. **Авторизация через VK-аккаунт** — OAuth flow, использовать user token вместо anonymous. В issue #48 обсуждают
3. **Кеширование credentials** — не дёргать API при каждом reconnect, переиспользовать пока не протухнут
4. **Подождать** — rate limit может быть временным

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
