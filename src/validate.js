'use strict';

// Правила валидации полей (совпадают с фронтендом ЛР 8).
// Каждый валидатор возвращает пустую строку или текст ошибки.

module.exports = {
  name(value) {
    return typeof value === 'string' && value.trim().length >= 2 ? '' : 'Имя: минимум 2 символа';
  },

  email(value) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value) ? '' : 'Некорректный email';
  },

  phone(value) {
    return /^\+?[0-9][0-9\s\-()]{8,18}$/.test(value) ? '' : 'Некорректный телефон';
  },

  password(value) {
    if (typeof value !== 'string' || value.length < 8) {
      return 'Пароль: минимум 8 символов';
    }
    if (!/[a-zа-яё]/i.test(value) || !/\d/.test(value)) {
      return 'Пароль должен содержать букву и цифру';
    }
    return '';
  },
};
