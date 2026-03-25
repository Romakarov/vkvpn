---
name: run-tests
description: >
  Прогнать все тесты, vet, проверить сборку.
  Use when: user says "тесты", "прогони тесты", "run tests", "проверь",
  "всё работает?", or before committing/deploying.
---

# Run Tests & Checks

## Выполнить последовательно

### 1. Go vet
```bash
cd /home/user/vkvpn && go vet ./...
```

### 2. Тесты с race detector
```bash
go test ./server/ ./pkg/... -v -race -count=1
```

### 3. Сборка сервера
```bash
go build -o /dev/null ./server/
```

### 4. Сборка клиента
```bash
go build -o /dev/null ./client/
```

### 5. Доложить результат
Формат:
```
✓ go vet — чисто
✓ тесты — N passed, 0 failed
✓ сборка сервера — ok
✓ сборка клиента — ok
```
или при ошибках:
```
✗ тесты — TestXxx FAILED: <причина>
  → <предложение фикса>
```

## Правила
- Если тесты падают — показать ошибку и предложить фикс
- Если go vet ругается — показать предупреждения
- НЕ пропускать ошибки молча
