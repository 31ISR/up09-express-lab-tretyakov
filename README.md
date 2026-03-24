# Проект: Book API

## Цель

- Создать REST API для управления библиотекой книг.
- Пользователи могут регистрироваться, авторизовываться, просматривать книги, а авторизованные — добавлять отзывы и управлять своими записями.
- Администратор имеет право управлять всеми книгами и пользователями.
- Необходимо внутри репозитория создать Bruno коллекцию, которая будет описывать эндпоинты вашего REST API сервера

_Хостить работу не надо_

Перед сдачей работы создать:
- 5 записей книг в БД
- 5 отзывов
- админа с кредами `admin:qwerty123`
- юзера `user:qwerty123`

---

## Основные сущности

### 1. `User`

| Поле        | Тип    | Описание                                  |
| ----------- | ------ | ----------------------------------------- |
| `id`        | number | Уникальный идентификатор                  |
| `username`  | string | Имя пользователя                          |
| `email`     | string | Email (уникальный)                        |
| `password`  | string | Хэшированный пароль                       |
| `role`      | string | Роль пользователя: `"user"` или `"admin"` |
| `createdAt` | date   | Дата регистрации                          |

---

### 2. `Book`

| Поле          | Тип                   | Описание                 |
| ------------- | --------------------- | ------------------------ |
| `id`          | number                | Уникальный идентификатор |
| `title`       | string                | Название книги           |
| `author`      | string                | Автор                    |
| `year`        | number                | Год издания              |
| `genre`       | string                | Жанр                     |
| `description` | string                | Описание                 |
| `createdBy`   | number (FK → User.id) | Кто добавил книгу        |
| `createdAt`   | date                  | Дата добавления          |

---

### 3. `Review`

| Поле        | Тип                   | Описание                 |
| ----------- | --------------------- | ------------------------ |
| `id`        | number                | Уникальный идентификатор |
| `bookId`    | number (FK → Book.id) | Книга                    |
| `userId`    | number (FK → User.id) | Автор отзыва             |
| `rating`    | number (1–5)          | Оценка                   |
| `comment`   | string                | Текст отзыва             |
| `createdAt` | date                  | Дата публикации          |

---

## Аутентификация

Использовать JWT (JSON Web Token).
Токен выдается при логине и передается в заголовке:
`Authorization: Bearer <token>`

---

## Эндпоинты

### Auth

| Метод  | URL                  | Описание                              | Доступ         |
| ------ | -------------------- | ------------------------------------- | -------------- |
| `POST` | `/api/auth/register` | Регистрация нового пользователя       | Публично       |
| `POST` | `/api/auth/login`    | Вход, получение JWT                   | Публично       |
| `GET`  | `/api/auth/profile`  | Получить данные текущего пользователя | Авторизованные |

---

### Books

| Метод    | URL              | Описание                                                  | Доступ         |
| -------- | ---------------- | --------------------------------------------------------- | -------------- |
| `GET`    | `/api/books`     | Получить список всех книг (с фильтрацией по жанру/автору) | Публично       |
| `GET`    | `/api/books/:id` | Получить книгу по ID (с отзывами)                         | Публично       |
| `POST`   | `/api/books`     | Добавить новую книгу                                      | Авторизованные |
| `PUT`    | `/api/books/:id` | Обновить книгу (только автор или админ)                   | Авторизованные |
| `DELETE` | `/api/books/:id` | Удалить книгу (только автор или админ)                    | Авторизованные |

---

### Reviews

| Метод  | URL                    | Описание                       | Доступ         |
| ------ | ---------------------- | ------------------------------ | -------------- |
| POST   | /api/books/:id/reviews | Добавить отзыв к книге         | Авторизованные |
| GET    | /api/books/:id/reviews | Получить все отзывы к книге    | Публично       |
| DELETE | /api/reviews/:id       | Удалить свой отзыв (или админ) | Авторизованные |

---

### Admin

| Метод  | URL                  | Описание                    | Доступ       |
| ------ | -------------------- | --------------------------- | ------------ |
| GET    | /api/admin/users     | Получить всех пользователей | Только админ |
| DELETE | /api/admin/users/:id | Удалить пользователя        | Только админ |

---

## Подсказки

### Использование внешних ключей

1. Включить поддержку внешних ключей

```js
const Database = require('better-sqlite3');
const db = new Database('library.db');

// Включаем поддержку внешних ключей
db.pragma('foreign_keys = ON');
```

---

2. Создать таблицы со связями

Каждая книга принадлежит какому-то пользователю (автору, который её добавил).

```js
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL
  );
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS books (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    author TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
`);
```

---

3. Вставка данных с учётом связи

Пример добавления пользователя и книги, связанной с ним по внешнему ключу:

```js
// Добавляем пользователя
const insertUser = db.prepare('INSERT INTO users (username, email) VALUES (?, ?)');
const result = insertUser.run('Alice', 'alice@example.com');

// Добавляем книгу, указывая id пользователя
const insertBook = db.prepare('INSERT INTO books (title, author, user_id) VALUES (?, ?, ?)');
insertBook.run('The Great Adventure', 'Alice Johnson', result.lastInsertRowid);

// либо если юзер уже существует
const userQuery = db.prepare('SELECT * FROM users WHERE id = ?')
const user = userQuery.get(id)

const book = db.prepare('INSERT INTO books (title, author, user_id) VALUES (?, ?, ?)');
insertBook.run('The Great Adventure', 'Alice Johnson', user.id);
```

---

Хочешь, я добавлю сюда раздел про выборку данных с `JOIN` и про поведение `ON DELETE CASCADE` (чтобы материал выглядел как законченная методичка для студентов)?

### Получение данных с join

```js
const booksWithUsers = db
    .prepare(
        ` SELECT books.id, books.title, books.author, users.username AS added_by FROM books JOIN users ON books.user_id = users.id `,
    )
    .all()
console.log(booksWithUsers)
```

Результат:

```json
[
    {
        "id": 1,
        "title": "The Great Adventure",
        "author": "Alice Johnson",
        "added_by": "Alice"
    }
]
```

### Проверка роли

В мидлварке проверки авторизации прикрепляем к запросу пользователя из базы данных

```js
const user = db
    .prepare(`SELECT * FROM users WHERE email = ?`)
    .get(email)
...
req.user = user // прикрепляем пользователя к запросу
```

Создаем мидлварку, которая будет проверять роль

```js
function checkRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ message: 'Пользователь не авторизован' });
    }

    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ message: 'Доступ запрещен: недостаточно прав' });
    }

    next();
  };
};

app.get('/users', auth, checkRole('admin'), (req, res) => {
...
}
```

Либо можно прямо в запросе, без дополнительного middleware делать проверку

```js
app.post('/users', auth, (req, res) => {
    if (!['admin'].includes(req.user.role)) {
        return res
            .status(403)
            .json({ message: 'Доступ запрещен: недостаточно прав' })
    }
})
```

## Документация

- [Express.js](https://expressjs.com/)
- [better-sqlite3](https://github.com/WiseLibs/better-sqlite3/blob/HEAD/docs/api.md)

# Как сдавать

- Создайте форк репозитория в вашей организации с названием-этого-репозитория-вашафамилия
- Используя ветку wip сделайте задание
- Зафиксируйте изменения в вашем репозитории
- Когда документ будет готов - создайте пул реквест из ветки wip (вашей) на ветку main (тоже вашу) и укажите меня (ktkv419) как reviewer

Не мержите сами коммит, это сделаю я после проверки задания
