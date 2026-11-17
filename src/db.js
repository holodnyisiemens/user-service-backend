'use strict';

// Слой доступа к PostgreSQL: пул соединений, схема и запросы.
// Таблицы: users (пользователи) и sessions (токены авторизации).

const { Pool } = require('pg');

function createDb(databaseUrl) {
  const pool = new Pool({ connectionString: databaseUrl });

  async function init() {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        phone TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        confirmed BOOLEAN NOT NULL DEFAULT FALSE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )
    `);
  }

  // Полная очистка таблиц (используется в тестах).
  async function clear() {
    await pool.query('TRUNCATE TABLE sessions, users');
  }

  async function createUser({ name, email, phone, passwordHash }) {
    const { rows } = await pool.query(
      'INSERT INTO users (name, email, phone, password_hash) VALUES ($1, $2, $3, $4) RETURNING id',
      [name, email, phone, passwordHash]
    );
    return rows[0];
  }

  async function findUserByEmail(email) {
    const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    return rows[0] || null;
  }

  async function setConfirmed(email) {
    await pool.query('UPDATE users SET confirmed = TRUE WHERE email = $1', [email]);
  }

  // Общие данные профиля (email — логин, поэтому не редактируется).
  async function updateProfile(email, { name, phone }) {
    const { rows } = await pool.query(
      `UPDATE users SET name = $1, phone = $2
       WHERE email = $3
       RETURNING name, email, phone, confirmed, created_at`,
      [name, phone, email]
    );
    return rows[0];
  }

  async function updatePassword(email, passwordHash) {
    await pool.query('UPDATE users SET password_hash = $1 WHERE email = $2', [passwordHash, email]);
  }

  async function createSession(userId, token) {
    await pool.query('INSERT INTO sessions (user_id, token) VALUES ($1, $2)', [userId, token]);
  }

  // Завершение всех сессий пользователя, кроме текущей (после смены пароля).
  async function deleteOtherSessions(userId, keepToken) {
    await pool.query('DELETE FROM sessions WHERE user_id = $1 AND token <> $2', [userId, keepToken]);
  }

  async function findUserByToken(token) {
    const { rows } = await pool.query(
      `SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = $1`,
      [token]
    );
    return rows[0] || null;
  }

  async function close() {
    await pool.end();
  }

  return {
    init,
    clear,
    createUser,
    findUserByEmail,
    setConfirmed,
    updateProfile,
    updatePassword,
    createSession,
    deleteOtherSessions,
    findUserByToken,
    close,
  };
}

module.exports = createDb;
