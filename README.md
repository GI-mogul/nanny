# Учет времени няни

## Быстрый хостинг с входом через Google

Для Gmail SSO нужен публичный HTTPS-адрес. Проще всего поднять это приложение как Node.js Web Service на Render или Railway.

Данные учета синхронизируются через сервер. Для общей истории на телефоне и десктопе подключите Postgres и передайте приложению `DATABASE_URL`.

### Вариант 1: Render

1. Загрузите проект в GitHub.
2. В Render создайте `Web Service` из репозитория.
3. Укажите:

```text
Build Command: npm install
Start Command: npm start
```

4. Добавьте переменные окружения:

```bash
GOOGLE_CLIENT_ID="..."
GOOGLE_CLIENT_SECRET="..."
SESSION_SECRET="long-random-string"
SESSION_TTL_SECONDS="604800"
DATABASE_URL="postgres://..."
ALLOWED_EMAILS="first@gmail.com,second@gmail.com,third@gmail.com"
PUBLIC_URL="https://your-app.onrender.com"
```

Если используете `render.yaml`, Render сам создаст поля переменных. Секретные значения нужно заполнить в Dashboard после создания сервиса.

### Общие данные между устройствами

1. В Render создайте Postgres database.
2. Скопируйте internal database URL.
3. В вашем Web Service откройте `Environment`.
4. Добавьте:

```text
DATABASE_URL=internal-postgres-url-from-render
```

5. Перезапустите сервис.

После этого записи, ставки и поездки будут храниться на сервере и будут видны с телефона и десктопа после входа через разрешенный Gmail.

5. В Google Cloud Console добавьте redirect URI:

```text
https://your-app.onrender.com/auth/google/callback
```

### Вариант 2: Railway

1. Загрузите проект в GitHub.
2. В Railway создайте проект из репозитория.
3. Railway сам увидит `npm start`.
4. Добавьте те же переменные окружения.
5. В `PUBLIC_URL` укажите публичный HTTPS-домен Railway.
6. В Google Cloud Console добавьте redirect URI:

```text
https://your-railway-domain/auth/google/callback
```

## Локальный запуск

1. Создайте OAuth Client в Google Cloud Console.
2. Добавьте redirect URI:

```text
http://127.0.0.1:3000/auth/google/callback
```

3. Заполните переменные окружения:

```bash
export GOOGLE_CLIENT_ID="..."
export GOOGLE_CLIENT_SECRET="..."
export SESSION_SECRET="long-random-string"
export ALLOWED_EMAILS="first@gmail.com,second@gmail.com,third@gmail.com"
export PUBLIC_URL="http://127.0.0.1:3000"
```

4. Запустите приложение:

```bash
node server.js
```

5. Откройте:

```text
http://127.0.0.1:3000
```

`index.html` по-прежнему можно открыть как обычный файл, но безопасный вход через Google работает только через `server.js`.
