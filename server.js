const crypto = require("crypto");
const fs = require("fs");
const http = require("http");
const https = require("https");
const path = require("path");
const { URL } = require("url");

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || "0.0.0.0";
const PUBLIC_URL = process.env.PUBLIC_URL || process.env.RENDER_EXTERNAL_URL;
const CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");
const SESSION_TTL_SECONDS = Number(process.env.SESSION_TTL_SECONDS || 7 * 24 * 60 * 60);
const SESSION_STORE_PATH = process.env.SESSION_STORE_PATH || path.join(__dirname, ".sessions.json");
const ALLOWED_EMAILS = new Set(
  (process.env.ALLOWED_EMAILS || "")
    .split(",")
    .map((email) => email.trim().toLowerCase())
    .filter(Boolean)
);

const sessions = new Map();
const oauthStates = new Map();
const publicFiles = new Map([
  ["/", "index.html"],
  ["/index.html", "index.html"]
]);

loadSessions();

function send(res, status, body, headers = {}) {
  res.writeHead(status, {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "same-origin",
    "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self' https://accounts.google.com",
    ...headers
  });
  res.end(body);
}

function redirect(res, location, headers = {}) {
  res.writeHead(302, {
    Location: location,
    "Cache-Control": "no-store",
    ...headers
  });
  res.end();
}

function parseCookies(req) {
  return Object.fromEntries(
    (req.headers.cookie || "")
      .split(";")
      .map((part) => part.trim().split("="))
      .filter(([name, value]) => name && value)
      .map(([name, value]) => [name, decodeURIComponent(value)])
  );
}

function sign(value) {
  return crypto.createHmac("sha256", SESSION_SECRET).update(value).digest("base64url");
}

function publicBaseUrl(req) {
  if (PUBLIC_URL) return PUBLIC_URL.replace(/\/$/, "");
  const proto = req.headers["x-forwarded-proto"] || "http";
  return `${proto}://${req.headers.host}`;
}

function makeCookie(name, value, maxAgeSeconds, secure = false) {
  const signed = `${value}.${sign(value)}`;
  return `${name}=${encodeURIComponent(signed)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAgeSeconds}${secure ? "; Secure" : ""}`;
}

function clearCookie(name) {
  return `${name}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`;
}

function readSignedCookie(req, name) {
  const raw = parseCookies(req)[name];
  if (!raw) return null;
  const lastDot = raw.lastIndexOf(".");
  if (lastDot === -1) return null;

  const value = raw.slice(0, lastDot);
  const signature = raw.slice(lastDot + 1);
  const expected = sign(value);
  if (signature.length !== expected.length) return null;
  if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return null;
  return value;
}

function currentUser(req) {
  const sessionId = readSignedCookie(req, "nanny_session");
  if (!sessionId) return null;

  const session = sessions.get(sessionId);
  if (!session || session.expiresAt < Date.now()) {
    sessions.delete(sessionId);
    saveSessions();
    return null;
  }

  return session.user;
}

function loadSessions() {
  try {
    const saved = JSON.parse(fs.readFileSync(SESSION_STORE_PATH, "utf8"));
    for (const [sessionId, session] of Object.entries(saved)) {
      if (session?.expiresAt > Date.now() && session?.user?.email) {
        sessions.set(sessionId, session);
      }
    }
  } catch {
    // No saved sessions yet.
  }
}

function saveSessions() {
  const activeSessions = Object.fromEntries(
    [...sessions.entries()].filter(([, session]) => session.expiresAt > Date.now())
  );
  fs.writeFile(SESSION_STORE_PATH, JSON.stringify(activeSessions), (error) => {
    if (error) console.error("Failed to save sessions:", error.message);
  });
}

function requireConfig(res) {
  if (CLIENT_ID && CLIENT_SECRET && ALLOWED_EMAILS.size > 0) return false;

  send(res, 500, `
    <main style="font-family: system-ui; max-width: 720px; margin: 48px auto; line-height: 1.5;">
      <h1>Нужно настроить вход через Google</h1>
      <p>Заполните переменные <code>GOOGLE_CLIENT_ID</code>, <code>GOOGLE_CLIENT_SECRET</code>, <code>ALLOWED_EMAILS</code> и перезапустите сервер.</p>
      <p>В Google OAuth redirect URI должен быть: <code>${PUBLIC_URL || `http://127.0.0.1:${PORT}`}/auth/google/callback</code></p>
    </main>
  `);
  return true;
}

function loginPage(res) {
  send(res, 200, `
    <!doctype html>
    <html lang="ru">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Вход</title>
      </head>
      <body style="margin:0; min-height:100vh; display:grid; place-items:center; background:#f7f2e9; color:#24302f; font-family:system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
        <main style="width:min(420px, calc(100% - 28px)); padding:24px; border:1px solid #ded7ca; border-radius:8px; background:white; box-shadow:0 18px 42px rgba(57,49,38,.12);">
          <h1 style="margin:0 0 10px; font-size:1.45rem;">Вход в учет времени</h1>
          <p style="margin:0 0 18px; color:#6b7471;">Доступ открыт только для разрешенных Gmail-аккаунтов.</p>
          <a href="/auth/google" style="height:48px; display:flex; align-items:center; justify-content:center; border-radius:6px; background:#2f7d6f; color:white; text-decoration:none; font-weight:750;">Войти через Google</a>
        </main>
      </body>
    </html>
  `);
}

function googleAuth(req, res) {
  if (requireConfig(res)) return;

  const state = crypto.randomBytes(24).toString("base64url");
  oauthStates.set(state, Date.now() + 10 * 60 * 1000);

  const redirectUri = `${publicBaseUrl(req)}/auth/google/callback`;
  const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  url.searchParams.set("client_id", CLIENT_ID);
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", "openid email profile");
  url.searchParams.set("state", state);
  url.searchParams.set("prompt", "select_account");

  redirect(res, url.toString(), {
    "Set-Cookie": makeCookie("nanny_oauth_state", state, 10 * 60, redirectUri.startsWith("https://"))
  });
}

async function googleCallback(req, res, url) {
  if (requireConfig(res)) return;

  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const cookieState = readSignedCookie(req, "nanny_oauth_state");
  const stateExpiresAt = oauthStates.get(state);

  if (!code || !state || state !== cookieState || !stateExpiresAt || stateExpiresAt < Date.now()) {
    send(res, 400, "Ошибка входа: неверное состояние авторизации.");
    return;
  }
  oauthStates.delete(state);

  try {
    const redirectUri = `${publicBaseUrl(req)}/auth/google/callback`;
    const token = await postForm("https://oauth2.googleapis.com/token", {
      code,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      redirect_uri: redirectUri,
      grant_type: "authorization_code"
    });
    const claims = parseJwt(token.id_token);
    const email = String(claims.email || "").toLowerCase();

    if (!claims.email_verified || !ALLOWED_EMAILS.has(email)) {
      send(res, 403, `
        <main style="font-family: system-ui; max-width: 620px; margin: 48px auto; line-height: 1.5;">
          <h1>Нет доступа</h1>
          <p>Аккаунт <strong>${escapeHtml(email || "без email")}</strong> не входит в список разрешенных пользователей.</p>
          <p><a href="/login">Вернуться ко входу</a></p>
        </main>
      `, { "Set-Cookie": clearCookie("nanny_oauth_state") });
      return;
    }

    const sessionId = crypto.randomBytes(32).toString("base64url");
    sessions.set(sessionId, {
      user: { email, name: claims.name || email },
      expiresAt: Date.now() + SESSION_TTL_SECONDS * 1000
    });
    saveSessions();

    redirect(res, "/", {
      "Set-Cookie": [
        clearCookie("nanny_oauth_state"),
        makeCookie("nanny_session", sessionId, SESSION_TTL_SECONDS, publicBaseUrl(req).startsWith("https://"))
      ]
    });
  } catch (error) {
    console.error(error);
    send(res, 500, "Не получилось завершить вход через Google.");
  }
}

function postForm(url, params) {
  return new Promise((resolve, reject) => {
    const body = new URLSearchParams(params).toString();
    const request = https.request(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": Buffer.byteLength(body)
      }
    }, (response) => {
      let data = "";
      response.setEncoding("utf8");
      response.on("data", (chunk) => data += chunk);
      response.on("end", () => {
        if (response.statusCode < 200 || response.statusCode >= 300) {
          reject(new Error(data));
          return;
        }
        resolve(JSON.parse(data));
      });
    });
    request.on("error", reject);
    request.end(body);
  });
}

function parseJwt(token) {
  const payload = token.split(".")[1];
  return JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;"
  })[char]);
}

function serveApp(req, res, fileName) {
  const user = currentUser(req);
  if (!user) {
    redirect(res, "/login");
    return;
  }

  const filePath = path.join(__dirname, fileName);
  fs.readFile(filePath, "utf8", (error, html) => {
    if (error) {
      send(res, 404, "Файл не найден.");
      return;
    }

    const banner = `
      <div class="auth-strip">
        <span>${escapeHtml(user.email)}</span>
        <a href="/logout">Выйти</a>
      </div>
    `;
    const protectedHtml = html.replace("<body>", `<body>${banner}`);
    send(res, 200, protectedHtml);
  });
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

  if (url.pathname === "/login") {
    if (currentUser(req)) redirect(res, "/");
    else loginPage(res);
    return;
  }

  if (url.pathname === "/auth/google") {
    googleAuth(req, res);
    return;
  }

  if (url.pathname === "/auth/google/callback") {
    googleCallback(req, res, url);
    return;
  }

  if (url.pathname === "/logout") {
    const sessionId = readSignedCookie(req, "nanny_session");
    if (sessionId) {
      sessions.delete(sessionId);
      saveSessions();
    }
    redirect(res, "/login", { "Set-Cookie": clearCookie("nanny_session") });
    return;
  }

  if (url.pathname === "/api/me") {
    const user = currentUser(req);
    if (!user) {
      send(res, 401, JSON.stringify({ user: null }), { "Content-Type": "application/json; charset=utf-8" });
      return;
    }
    send(res, 200, JSON.stringify({ user }), { "Content-Type": "application/json; charset=utf-8" });
    return;
  }

  const fileName = publicFiles.get(url.pathname);
  if (fileName) {
    serveApp(req, res, fileName);
    return;
  }

  send(res, 404, "Страница не найдена.");
});

server.on("error", (error) => {
  console.error(`Server failed to start: ${error.message}`);
  process.exit(1);
});

server.listen(PORT, HOST, () => {
  console.log(`Nanny tracker is running at http://${HOST}:${PORT}`);
});
