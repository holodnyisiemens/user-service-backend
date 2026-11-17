'use strict';

// Интеграционные тесты API против реального PostgreSQL.
// База для тестов: DATABASE_URL или postgres://postgres:postgres@localhost:5433/lab9
// (поднимается скриптом npm run db:up — Docker-контейнер с PostgreSQL).

const createServer = require('./src/server');

const DATABASE_URL = process.env.DATABASE_URL || 'postgres://postgres:postgres@localhost:5433/lab9';

const USER = {
  name: 'Алексей Устинов',
  email: 'ustinov@example.com',
  phone: '+7 999 123-45-67',
  password: 'Passw0rd',
};

let passed = 0;
const plan = [];

function check(name, condition) {
  plan.push(name);
  if (condition) passed++;
  console.log(`  ${condition ? 'OK  ' : 'ОШИБКА'} ${name}`);
}

async function api(base, method, pathname, { token, body } = {}) {
  const response = await fetch(base + pathname, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  let json = null;
  try {
    json = await response.json();
  } catch (e) {
    // тело отсутствует — оставляем null
  }
  return { status: response.status, json };
}

// Дождаться готовности БД (контейнер стартует не мгновенно).
async function waitForDb(db, attempts = 30) {
  for (let attempt = 1; ; attempt++) {
    try {
      await db.init();
      return;
    } catch (error) {
      if (attempt >= attempts) throw error;
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
  }
}

async function main() {
  const { server, db } = createServer({ databaseUrl: DATABASE_URL });
  await waitForDb(db);
  await new Promise((resolve) => server.listen(0, resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  await db.clear();

  console.log('--- Здоровье сервиса ---');
  const health = await api(base, 'GET', '/api/health');
  check('GET /api/health отвечает 200', health.status === 200 && health.json.ok === true);

  console.log('--- Регистрация ---');
  const reg = await api(base, 'POST', '/api/register', { body: USER });
  check('корректные данные -> 201', reg.status === 201 && reg.json.email === USER.email);
  const dup = await api(base, 'POST', '/api/register', { body: { ...USER, phone: '+7 999 000-00-00' } });
  check('дубликат email -> 409', dup.status === 409);
  const weak = await api(base, 'POST', '/api/register', { body: { ...USER, email: 'a@b.co', password: '123' } });
  check('слабый пароль -> 400', weak.status === 400);
  const badMail = await api(base, 'POST', '/api/register', { body: { ...USER, email: 'not-an-email' } });
  check('невалидный email -> 400', badMail.status === 400);
  const badPhone = await api(base, 'POST', '/api/register', { body: { ...USER, email: 'c@d.co', phone: 'abc' } });
  check('невалидный телефон -> 400', badPhone.status === 400);

  console.log('--- Подтверждение почты ---');
  const early = await api(base, 'POST', '/api/login', { body: { email: USER.email, password: USER.password } });
  check('вход до подтверждения -> 403', early.status === 403);
  const wrongCode = await api(base, 'POST', '/api/confirm', { body: { email: USER.email, code: '000000' } });
  check('неверный код -> 400', wrongCode.status === 400);
  const confirmed = await api(base, 'POST', '/api/confirm', { body: { email: USER.email, code: '123456' } });
  check('захардкоженный код -> 200', confirmed.status === 200);

  console.log('--- Логин и сессия ---');
  const badLogin = await api(base, 'POST', '/api/login', { body: { email: USER.email, password: 'WrongPass1' } });
  check('неверный пароль -> 401', badLogin.status === 401);
  const login = await api(base, 'POST', '/api/login', { body: { email: USER.email, password: USER.password } });
  check('верные данные -> токен', login.status === 200 && typeof login.json.token === 'string');
  const token = login.json.token;

  console.log('--- Профиль (общие данные) ---');
  const noAuth = await api(base, 'GET', '/api/me');
  check('запрос без токена -> 401', noAuth.status === 401);
  const me = await api(base, 'GET', '/api/me', { token });
  check('GET /api/me возвращает профиль', me.status === 200 && me.json.user.email === USER.email);
  const updated = await api(base, 'PUT', '/api/me', {
    token,
    body: { name: 'Алексей К.', phone: '+7 900 555-01-02' },
  });
  check('PUT /api/me сохраняет имя и телефон', updated.status === 200 && updated.json.user.name === 'Алексей К.');
  const meAgain = await api(base, 'GET', '/api/me', { token });
  check('телефон реально сохранился в БД', meAgain.json.user.phone === '+7 900 555-01-02');
  const badProfile = await api(base, 'PUT', '/api/me', { token, body: { name: 'Алексей К.', phone: 'abc' } });
  check('плохой телефон в профиле -> 400', badProfile.status === 400);

  console.log('--- Безопасность (смена пароля) ---');
  const wrongCurrent = await api(base, 'PUT', '/api/me/password', {
    token,
    body: { current: 'nope', next: 'NewPass123', repeat: 'NewPass123' },
  });
  check('неверный текущий пароль -> 400', wrongCurrent.status === 400);
  const mismatch = await api(base, 'PUT', '/api/me/password', {
    token,
    body: { current: USER.password, next: 'NewPass123', repeat: 'NewPass124' },
  });
  check('несовпадение повтора -> 400', mismatch.status === 400);

  // Вторая сессия: после смены пароля она должна быть завершена.
  const login2 = await api(base, 'POST', '/api/login', { body: { email: USER.email, password: USER.password } });
  const token2 = login2.json.token;

  const changed = await api(base, 'PUT', '/api/me/password', {
    token,
    body: { current: USER.password, next: 'NewPass123', repeat: 'NewPass123' },
  });
  check('смена пароля -> 200', changed.status === 200);
  const oldLogin = await api(base, 'POST', '/api/login', { body: { email: USER.email, password: USER.password } });
  check('старый пароль больше не пускает', oldLogin.status === 401);
  const oldSession = await api(base, 'GET', '/api/me', { token: token2 });
  check('вторая сессия завершена после смены пароля', oldSession.status === 401);
  const currentSession = await api(base, 'GET', '/api/me', { token });
  check('текущая сессия сохранилась', currentSession.status === 200);
  const newLogin = await api(base, 'POST', '/api/login', { body: { email: USER.email, password: 'NewPass123' } });
  check('новый пароль работает', newLogin.status === 200);

  console.log(`\nпройдено ${passed}/${plan.length} проверок`);
  server.close();
  await db.close();
  if (passed !== plan.length) process.exitCode = 1;
}

main().catch((error) => {
  console.error('Тесты не выполнены:', error.message);
  console.error('Убедитесь, что PostgreSQL доступен (npm run db:up) или задайте DATABASE_URL.');
  process.exit(1);
});
