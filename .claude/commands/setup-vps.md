---
name: setup-vps
description: >
  Полная настройка VPS с нуля для VKVPN сервера.
  Use when: user says "настрой VPS", "setup VPS", "подними сервер",
  "новый сервер", "установи на VPS", "с нуля".
---

# Setup VPS from Scratch

## Порядок действий

### 1. Узнать доступы
Спроси у пользователя (если нет в контексте):
- IP адрес VPS
- SSH доступ (root@IP, ключ или пароль)

### 2. Проверить доступ
```bash
ssh root@<VPS_IP> 'uname -a && cat /etc/os-release | head -5'
```
Убедиться: Ubuntu 24.04, root доступ.

### 3. Загрузить install.sh
```bash
scp /home/user/vkvpn/install.sh root@<VPS_IP>:/tmp/vkvpn-install.sh
```

### 4. Запустить установку
```bash
ssh root@<VPS_IP> 'bash /tmp/vkvpn-install.sh'
```
Это установит: WireGuard, создаст конфиг, systemd-сервис, откроет порты.

**Сохранить из вывода:**
- Admin password
- Server IP

### 5. Собрать и загрузить бинарник
```bash
cd /home/user/vkvpn
GOOS=linux GOARCH=amd64 go build -ldflags '-s -w' -trimpath -o /tmp/vkvpn-server ./server/
scp /tmp/vkvpn-server root@<VPS_IP>:/opt/vkvpn/server
```

### 6. Запустить сервис
```bash
ssh root@<VPS_IP> 'chmod +x /opt/vkvpn/server && systemctl start vkvpn && sleep 2 && systemctl status vkvpn'
```

### 7. Проверить работу
```bash
ssh root@<VPS_IP> 'curl -s http://localhost:8080/api/status?token=<ADMIN_PASS>'
```

### 8. Доложить
Сообщить пользователю:
- Админка: `http://<VPS_IP>:8080/?token=<ADMIN_PASS>`
- WireGuard: порт 51820/udp
- DTLS: порт 56000/udp
- Как подключить клиентов

## Диагностика проблем
```bash
# Логи сервиса
ssh root@<VPS_IP> 'journalctl -u vkvpn -n 100 --no-pager'

# WireGuard статус
ssh root@<VPS_IP> 'wg show'

# Порты
ssh root@<VPS_IP> 'ss -ulnp | grep -E "51820|56000|8080"'

# Firewall
ssh root@<VPS_IP> 'ufw status'
```

## Правила
- НИКОГДА не хардкодить IP, пароли, ключи
- Сохранять admin password из вывода install.sh и показать пользователю
- Если VPS уже настроен (config.json существует) — предупредить и не перетирать конфиг
