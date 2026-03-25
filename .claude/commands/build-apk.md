---
name: build-apk
description: >
  Собрать Android APK локально или через CI.
  Use when: user says "собери APK", "build APK", "андроид сборка",
  "обнови приложение", "build android".
---

# Build Android APK

## Вариант 1: Через CI (рекомендуется)
```bash
# Push изменений в main триггерит .github/workflows/build-apk.yml
git push origin main
```
CI соберёт APK автоматически и загрузит как артефакт.

## Вариант 2: Локально

### Предварительные требования
- Go 1.25+
- Java 17 (JDK)
- Android SDK (compileSdk 35)
- Android NDK 27
- gomobile (`go install golang.org/x/mobile/cmd/gomobile@latest && gomobile init`)

### Шаги

#### 1. Собрать gomobile AAR
```bash
cd /home/user/vkvpn
gomobile bind -target=android -androidapi 26 -o android/app/libs/tunnel.aar ./android/tunnel/
```

#### 2. Собрать APK
```bash
cd android
./gradlew assembleDebug
```

#### 3. APK будет здесь
```
android/app/build/outputs/apk/debug/app-debug.apk
```

### Если gomobile падает с go:linkname
Есть патч в CI (`build-apk.yml`) — нужно применить его к файлу `anet`:
```bash
ANET=$(find ~/go -path "*/internal/anet/anet.go" 2>/dev/null | head -1)
if [ -n "$ANET" ]; then
  # Добавить //go:linkname для Android совместимости
  # См. .github/workflows/build-apk.yml для деталей патча
fi
```

## Правила
- Для production-релиза: `./gradlew assembleRelease` (нужен signing key)
- Не коммитить APK/AAR в репо (есть в .gitignore)
- При ошибках сборки — проверить версии SDK/NDK/Go
