'use strict';

// Бэкенд сервиса управления пользователями — JSON API поверх PostgreSQL.
// HTTP-сервер на встроенном модуле http (без фреймворков), драйвер pg.
// Сценарии совпадают с фронтендом ЛР 8: регистрация, подтверждение почты
// захардкоженным кодом, логин (токен), профиль, смена пароля.
// Кроме API сервер может раздавать статику фронтенда ЛР 8 (FRONTEND_DIR).

const http = require('http');
const fs = require('fs');
const path = require('path');
const createDb = require('./db');
const validate = require('./validate');
const security = require('./security');

const PORT = Number(process.env.PORT || 3000);
const DATABASE_URL = process.env.DATABASE_URL || 'postgres://postgres:postgres@localhost:5433/lab9';
const CONFIRM_CODE = process.env.CONFIRM_CODE || '123456'; // захардкоженный код подтверждения

// Фронтенд ЛР 8: ищем рядом с lab9 или в соседней папке «ЛР 8» (структура ЛР N/labN).
function resolveFrontendDir() {
  if (process.env.FRONTEND_DIR) return process.env.FRONTEND_DIR;
  const candidates = [
    path.join(__dirname, '..', '..', 'lab8'),
    path.join(__dirname, '..', '..', '..', 'ЛР 8', 'lab8'),
  ];
  return (
    candidates.find((dir) => {
      try {
        return fs.statSync(dir).isDirectory();
      } catch (e) {
        return false;
      }
    }) || ''
  );
}
const FRONTEND_DIR = resolveFrontendDir();

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
};

function send(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(data));
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', (chunk) => {
      raw += chunk;
      if (raw.length > 100_000) {
        const error = new Error('Слишком большое тело запроса');
        error.statusCode = 413;
        reject(error);
        req.destroy();
      }
    });
    req.on('end', () => {
      if (!raw) return resolve({});
      try {
        resolve(JSON.parse(raw));
      } catch (e) {
        const error = new Error('Невалидный JSON');
        error.statusCode = 400;
        reject(error);
      }
    });
    req.on('error', reject);
  });
}

function publicUser(row) {
  return {
    name: row.name,
    email: row.email,
    phone: row.phone,
    confirmed: row.confirmed,
    createdAt: row.created_at,
  };
}

function createServer(overrides = {}) {
  const db = createDb(overrides.databaseUrl || DATABASE_URL);
  const confirmCode = overrides.confirmCode || CONFIRM_CODE;

  async function register(res, body) {
    const name = String(body.name || '').trim();
    const email = String(body.email || '').trim().toLowerCase();
    const phone = String(body.phone || '').trim();
    const password = String(body.password || '');

    const fieldError =
      validate.name(name) || validate.email(email) || validate.phone(phone) || validate.password(password);
    if (fieldError) return send(res, 400, { error: fieldError });

    try {
      await db.createUser({ name, email, phone, passwordHash: security.hashPassword(password) });
    } catch (e) {
      if (e.code === '23505') {
        return send(res, 409, { error: 'Пользователь с таким email уже зарегистрирован' });
      }
      throw e;
    }
    console.log(`[emulation] Письмо для ${email}: код подтверждения ${confirmCode}`);
    return send(res, 201, { email });
  }

  async function confirm(res, body) {
    const email = String(body.email || '').trim().toLowerCase();
    const user = await db.findUserByEmail(email);
    if (!user) return send(res, 404, { error: 'Пользователь не найден' });
    if (String(body.code || '').trim() !== confirmCode) {
      return send(res, 400, { error: 'Неверный код подтверждения' });
    }
    await db.setConfirmed(email);
    return send(res, 200, { email });
  }

  async function login(res, body) {
    const email = String(body.email || '').trim().toLowerCase();
    const user = await db.findUserByEmail(email);
    if (!user || !security.verifyPassword(body.password, user.password_hash)) {
      return send(res, 401, { error: 'Неверный email или пароль' });
    }
    if (!user.confirmed) {
      return send(res, 403, { error: 'Почта не подтверждена — сначала введите код из письма' });
    }
    const token = security.newToken();
    await db.createSession(user.id, token);
    return send(res, 200, { token });
  }

  async function authenticate(req, res) {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice('Bearer '.length) : null;
    const user = token ? await db.findUserByToken(token) : null;
    if (!user) {
      send(res, 401, { error: 'Требуется авторизация' });
      return null;
    }
    return user;
  }

  async function me(req, res) {
    const user = await authenticate(req, res);
    if (user) send(res, 200, { user: publicUser(user) });
  }

  async function updateMe(req, res, body) {
    const user = await authenticate(req, res);
    if (!user) return;
    const name = String(body.name || '').trim();
    const phone = String(body.phone || '').trim();
    const fieldError = validate.name(name) || validate.phone(phone);
    if (fieldError) return send(res, 400, { error: fieldError });
    const updated = await db.updateProfile(user.email, { name, phone });
    return send(res, 200, { user: updated });
  }

  async function changePassword(req, res, body) {
    const user = await authenticate(req, res);
    if (!user) return;
    if (!security.verifyPassword(body.current, user.password_hash)) {
      return send(res, 400, { error: 'Текущий пароль неверный' });
    }
    const next = String(body.next || '');
    if (next !== String(body.repeat || '')) {
      return send(res, 400, { error: 'Новые пароли не совпадают' });
    }
    const fieldError = validate.password(next);
    if (fieldError) return send(res, 400, { error: fieldError });
    if (security.verifyPassword(next, user.password_hash)) {
      return send(res, 400, { error: 'Новый пароль совпадает со старым' });
    }
    await db.updatePassword(user.email, security.hashPassword(next));
    // остальные сессии пользователя завершаются, текущая сохраняется
    const token = (req.headers.authorization || '').slice('Bearer '.length);
    await db.deleteOtherSessions(user.id, token);
    return send(res, 200, { ok: true });
  }

  async function serveStatic(res, pathname) {
    const rel = pathname === '/' ? 'index.html' : pathname;
    const root = path.normalize(FRONTEND_DIR);
    const filePath = path.normalize(path.join(root, rel));
    if (!filePath.startsWith(root)) return send(res, 403, { error: 'Доступ запрещён' });
    fs.readFile(filePath, (error, content) => {
      if (error) return send(res, 404, { error: 'Не найдено' });
      res.writeHead(200, { 'Content-Type': MIME[path.extname(filePath)] || 'application/octet-stream' });
      res.end(content);
    });
  }

  async function handle(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    const { pathname } = new URL(req.url, 'http://localhost');
    const body = req.method === 'POST' || req.method === 'PUT' ? await readJson(req) : {};

    if (req.method === 'GET' && pathname === '/api/health') return send(res, 200, { ok: true });
    if (req.method === 'POST' && pathname === '/api/register') return register(res, body);
    if (req.method === 'POST' && pathname === '/api/confirm') return confirm(res, body);
    if (req.method === 'POST' && pathname === '/api/login') return login(res, body);
    if (req.method === 'GET' && pathname === '/api/me') return me(req, res);
    if (req.method === 'PUT' && pathname === '/api/me') return updateMe(req, res, body);
    if (req.method === 'PUT' && pathname === '/api/me/password') return changePassword(req, res, body);
    if (req.method === 'GET' && FRONTEND_DIR && fs.existsSync(FRONTEND_DIR)) {
      return serveStatic(res, pathname);
    }
    return send(res, 404, { error: 'Не найдено' });
  }

  const server = http.createServer((req, res) => {
    handle(req, res).catch((error) => {
      console.error(error);
      if (!res.headersSent) send(res, error.statusCode || 500, { error: error.message || 'Внутренняя ошибка сервера' });
    });
  });

  return { server, db };
}

async function main() {
  const { server, db } = createServer();
  await db.init();
  server.listen(PORT, () => {
    console.log(`Сервер запущен: http://localhost:${PORT}`);
    console.log(`База данных: PostgreSQL (${DATABASE_URL.split('@')[1] || DATABASE_URL})`);
    console.log(`Фронтенд ЛР 8: ${fs.existsSync(FRONTEND_DIR) ? `раздаётся из ${FRONTEND_DIR}` : 'не найден (FRONTEND_DIR)'}`);
  });
}

if (require.main === module) {
  main().catch((error) => {
    console.error('Не удалось запустить сервер:', error.message);
    process.exit(1);
  });
}

module.exports = createServer;
