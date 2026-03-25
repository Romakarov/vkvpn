---
name: diagnose-vps
description: >
  Диагностика проблем на VPS: сервис, WireGuard, сеть, логи.
  Use when: user says "не работает", "проверь сервер", "diagnose",
  "что с VPS", "логи", "почему не подключается", "debug server".
---

# Diagnose VPS Issues

## Порядок диагностики

Спроси доступ к VPS если нет в контексте (`root@IP`).

### 1. Статус сервисов
```bash
ssh root@<VPS_IP> 'systemctl status vkvpn --no-pager && echo "---" && systemctl status wg-quick@wg0 --no-pager'
```

### 2. Логи VKVPN
```bash
ssh root@<VPS_IP> 'journalctl -u vkvpn -n 100 --no-pager'
```

### 3. WireGuard
```bash
ssh root@<VPS_IP> 'wg show'
```

### 4. Порты
```bash
ssh root@<VPS_IP> 'ss -ulnp | grep -E "51820|56000|8080"'
```
Ожидается:
- 51820/udp — WireGuard
- 56000/udp — DTLS listener
- 8080/tcp — HTTP API

### 5. Firewall
```bash
ssh root@<VPS_IP> 'ufw status verbose 2>/dev/null || iptables -L -n | head -30'
```

### 6. IP forwarding
```bash
ssh root@<VPS_IP> 'sysctl net.ipv4.ip_forward'
```
Должно быть `= 1`.

### 7. Конфигурация
```bash
ssh root@<VPS_IP> 'cat /etc/vkvpn/config.json | python3 -c "import sys,json; d=json.load(sys.stdin); del d[\"server_private_key\"]; del d[\"admin_pass\"]; print(json.dumps(d,indent=2))"'
```
(показываем конфиг БЕЗ приватных данных)

### 8. API health check
```bash
ssh root@<VPS_IP> 'curl -s http://localhost:8080/api/status?token=$(python3 -c "import json; print(json.load(open(\"/etc/vkvpn/config.json\"))[\"admin_pass\"])")'
```

### 9. Доклад
Сообщить:
- Что работает / не работает
- Причина проблемы
- Конкретные шаги для исправления

## Типичные проблемы

| Симптом | Причина | Решение |
|---------|---------|---------|
| vkvpn не стартует | Бинарник не найден | Задеплоить через `/deploy` |
| Port 56000 не слушает | vkvpn упал | Проверить логи, рестартнуть |
| WG handshake не проходит | Firewall блокирует 51820 | `ufw allow 51820/udp` |
| Нет интернета через VPN | ip_forward=0 | `sysctl -w net.ipv4.ip_forward=1` |
| Нет NAT | iptables правила нет | Рестартнуть wg-quick@wg0 |

## Правила
- НЕ показывать приватные ключи и пароли в выводе
- Если нужен рестарт — спросить пользователя
- Если конфиг битый — предложить восстановить из бэкапа
