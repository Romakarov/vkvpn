---
name: deploy
description: >
  Собрать и задеплоить VKVPN сервер на VPS.
  Use when: user says "деплой", "deploy", "залей на сервер", "обнови сервер",
  "выкати", "push to production", or after completing a server-side feature.
---

# Deploy VKVPN Server

## Порядок действий

### 1. Прогнать тесты
```bash
go test ./server/ ./pkg/... -v -race
```
Если тесты падают — СТОП. Не деплоить. Сначала починить.

### 2. Собрать бинарник
```bash
cd /home/user/vkvpn
GOOS=linux GOARCH=amd64 go build -ldflags '-s -w' -trimpath -o /tmp/vkvpn-server ./server/
```

### 3. Загрузить на VPS
Спроси у пользователя адрес VPS если не известен (`root@IP`).
```bash
scp /tmp/vkvpn-server root@<VPS_IP>:/opt/vkvpn/server
```

### 4. Рестартнуть сервис
```bash
ssh root@<VPS_IP> 'systemctl restart vkvpn && sleep 2 && systemctl status vkvpn'
```

### 5. Проверить health
```bash
ssh root@<VPS_IP> 'curl -s http://localhost:8080/api/status?token=$(python3 -c "import json; print(json.load(open(\"/etc/vkvpn/config.json\"))[\"admin_pass\"])")'
```

### 6. Доложить результат
Сообщить пользователю:
- Версия задеплоена
- Сервис работает / не работает
- Если ошибка — показать логи: `journalctl -u vkvpn -n 50 --no-pager`

## Правила
- НИКОГДА не деплоить без прогона тестов
- НИКОГДА не хардкодить IP/ключи — спрашивать или брать из контекста
- Если deploy.sh уже существует, можно использовать его: `./deploy.sh root@<VPS_IP>`
- При ошибке деплоя — показать логи и предложить откат
