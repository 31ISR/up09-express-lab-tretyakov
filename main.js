const express = require("express")
const db = require("./db")
const jwt = require("jsonwebtoken")
const bcr = require("bcryptjs")
const app = express()
const SECRET = "Крутые бобры"

const auth = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1]
    if (!token) {
        return res.status(401).json({error: "Нет токена"})
    }

    try {
        const decoded = jwt.verify(token, SECRET)
        req.user = decoded
        next()
    } catch (error) {
        return res.status(401).json({error: "Неверный токен"})
    }
}

app.use(express.json())

app.get("/users", (req, res) => {
    const users = db.prepare("SELECT id, username, email, role, createdAt FROM users").all()
    return res.status(200).json(users)
})

app.post("/api/auth/register", async (req, res) => {
    try { 
        const {username, email, password} = req.body
        
        if (!username || !email || !password) {
            return res.status(400).json({message: "Все поля обязательны"})
        }
        
        const hashedPassword = await bcr.hash(password, 10)
        const query = db.prepare(`INSERT INTO users (username, email, password) VALUES (?, ?, ?)`).run(username, email, hashedPassword)
        const newUser = db.prepare("SELECT id, username, email, role, createdAt FROM users WHERE id = ?").get(query.lastInsertRowid)
        
        res.status(201).json({message: "Пользователь успешно зарегистрирован", user: newUser})
    } catch (error) {
        if (error.message.includes("UNIQUE constraint failed")) {
            res.status(400).json({message: "Пользователь с таким email или username уже существует"})
        } else {
            res.status(500).json({message: "Что-то пошло не так"})
        }
    }
})

app.post("/api/auth/login", async (req, res) => {
    try {
        const { email, password } = req.body

        if (!email || !password) {
            return res.status(400).json({ error: "Email и пароль обязательны" })
        }

        const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email)
        if (!user) {
            return res.status(401).json({ error: "Неверный email или пароль" })
        }

        const isValidPassword = await bcr.compare(password, user.password)
        if (!isValidPassword) {
            return res.status(401).json({ error: "Неверный email или пароль" })
        }

        const { password: _, ...safeUser } = user
        const token = jwt.sign(safeUser, SECRET, { expiresIn: "24h" })
        
        return res.status(200).json({ 
            success: true, 
            token, 
            user: safeUser,
            error: null 
        })

    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Ошибка сервера" })
    }
})

app.get("/api/auth/profile", auth, (req, res) => {
    try {
        const user = db.prepare("SELECT id, username, email, role, createdAt FROM users WHERE id = ?").get(req.user.id)

        if (!user) {
            return res.status(404).json({error: "Пользователь не найден"})
        }

        res.json({success: true, user})
    } catch (error) {
        res.status(500).json({error: "Ошибка сервера"})
    }
})

app.get("/api/books", (req, res) => {
    try {
        const { genre, author } = req.query
        let query = "SELECT * FROM book"
        const conditions = []
        const params = []
        if (genre) {
            conditions.push("genre = ?")
            params.push(genre)
        }
        if (author) {
            conditions.push("автор = ?")
            params.push(author)
        }
        if (conditions.length > 0) {
          query += " WHERE " + conditions.join(" AND ")
        }
        const books = db.prepare(query).all(...params)
        res.status(200).json(books)
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Ошибка сервера" })
    }
})

app.post("/api/books/:id", (req, res) => {
    try {
        const { id } = req.params
        const book = db.prepare(`
            SELECT book.*, users.username as createdByUsername 
            FROM book 
            LEFT JOIN users ON book.CreatedBy = users.id 
            WHERE book.id = ?
        `).get(id)
        if (!book) {
            return res.status(404).json({ error: "Книга не найдена" })
        }
        res.status(200).json(book)
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Ошибка сервера" })
    }
})

app.post("/api/books", auth, (req, res) => {
    try {
        const { title, author, year, genre, description } = req.body
        if (!title || !author || !year || !genre || !description) {
            return res.status(400).json({ error: "Все поля обязательны" })
        }
        const query = db.prepare(`
            INSERT INTO book (title, author, year, genre, description, CreatedBy) 
            VALUES (?, ?, ?, ?, ?, ?)
        `)
        const result = query.run(title, author, year, genre, description, req.user.id)
        const newBook = db.prepare(`
            SELECT book.*, users.username as createdByUsername 
            FROM book 
            LEFT JOIN users ON book.CreatedBy = users.id 
            WHERE book.id = ?
        `).get(result.lastInsertRowid)
        res.status(201).json({ message: "Книга успешно добавлена", book: newBook })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Ошибка сервера", details: error.message })
    }
})

app.put("/api/books/:id", auth, (req, res) => {
    try {
        const { id } = req.params
        const { title, author, year, genre, description } = req.body
        const book = db.prepare("SELECT * FROM book WHERE id = ?").get(id)
        if (!book) {
            return res.status(404).json({ error: "Книга не найдена" })
        }
        if (book.CreatedBy !== req.user.id) {
            return res.status(403).json({ error: "Вы можете редактировать только свои книги" })
        }
        const updates = []
        const params = []
        if (title !== undefined) {
            updates.push("title = ?")
            params.push(title)
        }
        if (author !== undefined) {
            updates.push("author = ?")
            params.push(author)
        }
        if (year !== undefined) {
            updates.push("year = ?")
            params.push(year)
        }
        if (genre !== undefined) {
            updates.push("genre = ?")
            params.push(genre)
        }
        if (description !== undefined) {
            updates.push("description = ?")
            params.push(description)
        }
        if (updates.length === 0) {
            return res.status(400).json({ error: "Нет полей для обновления" })
        }
        params.push(id)
        const query = db.prepare(`UPDATE book SET ${updates.join(", ")} WHERE id = ?`)
        query.run(...params)
        const updatedBook = db.prepare(`
            SELECT book.*, users.username as createdByUsername 
            FROM book 
            LEFT JOIN users ON book.CreatedBy = users.id 
            WHERE book.id = ?
        `).get(id)
        res.status(200).json({ 
            message: "Книга успешно обновлена", 
            book: updatedBook 
        })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Ошибка сервера", details: error.message })
    }
})

app.delete("/api/books/:id", auth, (req, res) => {
    try {
        const { id } = req.params
        const book = db.prepare("SELECT * FROM book WHERE id = ?").get(id)
        if (!book) {
            return res.status(404).json({ error: "Книга не найдена" })
        }
        if (book.CreatedBy !== req.user.id) {
            return res.status(403).json({ error: "Вы можете удалять только свои книги" })
        }
        db.prepare("DELETE FROM book WHERE id = ?").run(id)
        res.status(200).json({ 
            message: "Книга успешно удалена",
            deletedBook: {
                id: book.id,
                title: book.title,
                author: book.author
            }
        })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Ошибка сервера", details: error.message })
    }
})

app.post("/api/books/:id/reviews", auth, (req, res) => {
    try {
        const { id } = req.params
        const { rating, comment } = req.body
        const book = db.prepare("SELECT * FROM book WHERE id = ?").get(id)
        if (!book) {
            return res.status(404).json({ error: "Книга не найдена" })
        }
        if (!rating || !comment) {
            return res.status(400).json({ error: "Рейтинг и комментарий обязательны" })
        }
        if (rating < 1 || rating > 5) {
            return res.status(400).json({ error: "Рейтинг должен быть от 1 до 5" })
        }
        const existingReview = db.prepare(
            "SELECT * FROM reviews WHERE bookId = ? AND userId = ?"
        ).get(id, req.user.id)
        const query = db.prepare(`
            INSERT INTO reviews (bookId, userId, rating, comment) 
            VALUES (?, ?, ?, ?)
        `)
        const result = query.run(id, req.user.id, rating, comment)
        const newReview = db.prepare(`
            SELECT reviews.*, users.username 
            FROM reviews 
            LEFT JOIN users ON reviews.userId = users.id 
            WHERE reviews.id = ?
        `).get(result.lastInsertRowid)
        res.status(201).json({ 
            message: "Отзыв успешно добавлен", 
            review: newReview 
        })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Ошибка сервера", details: error.message })
    }
})

app.get("/api/books/:id/reviews", (req, res) => {
    try {
        const { id } = req.params
        const book = db.prepare("SELECT id, title FROM book WHERE id = ?").get(id)
        if (!book) {
            return res.status(404).json({ error: "Книга не найдена" })
        }
        const reviews = db.prepare(`
            SELECT 
                reviews.id,
                reviews.rating,
                reviews.comment,
                reviews.createdAt,
                users.username
            FROM reviews 
            LEFT JOIN users ON reviews.userId = users.id 
            WHERE reviews.bookId = ?
            ORDER BY reviews.createdAt DESC
        `).all(id)
        const avgRating = db.prepare(`
            SELECT AVG(rating) as averageRating, COUNT(*) as totalReviews
            FROM reviews 
            WHERE bookId = ?
        `).get(id)
        res.status(200).json({
            book: {
                id: book.id,
                title: book.title
            },
            statistics: {
                totalReviews: avgRating.totalReviews,
                averageRating: avgRating.averageRating ? avgRating.averageRating.toFixed(1) : null
            },
            reviews: reviews
        })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Ошибка сервера", details: error.message })
    }
})

app.delete("/api/reviews/:id", auth, (req, res) => {
    try {
        const { id } = req.params
        const review = db.prepare("SELECT * FROM reviews WHERE id = ?").get(id)
        if (!review) {
            return res.status(404).json({ error: "Отзыв не найден" })
        }
        if (review.userId !== req.user.id) {
            return res.status(403).json({ error: "Вы можете удалять только свои отзывы" })
        }
        db.prepare("DELETE FROM reviews WHERE id = ?").run(id)
        res.status(200).json({ 
            message: "Отзыв успешно удалён",
            deletedReview: {
                id: review.id,
                bookId: review.bookId,
                rating: review.rating,
                comment: review.comment
            }
        })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Ошибка сервера", details: error.message })
    }
})

app.post("/api/users/make-admin", auth, async (req, res) => {
    try {
        db.prepare("UPDATE users SET role = 'admin' WHERE id = ?").run(req.user.id)
        const updatedUser = db.prepare(
            "SELECT id, username, email, role, createdAt FROM users WHERE id = ?"
        ).get(req.user.id)
        const token = jwt.sign(updatedUser, SECRET, { expiresIn: "24h" })
        res.status(200).json({ 
            message: "Поздравляю! Вы теперь администратор!", 
            user: updatedUser,
            token: token 
        })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Ошибка сервера", details: error.message })
    }
})

app.get("/api/admin/users", auth, (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ error: "Доступ запрещён. Требуются права администратора" })
        }
        const users = db.prepare(`
            SELECT 
                users.id,
                users.username,
                users.email,
                users.role,
                users.createdAt,
                COUNT(DISTINCT book.id) as booksCount,
                COUNT(DISTINCT reviews.id) as reviewsCount
            FROM users 
            LEFT JOIN book ON users.id = book.CreatedBy
            LEFT JOIN reviews ON users.id = reviews.userId
            GROUP BY users.id
            ORDER BY users.createdAt DESC
        `).all()
        const stats = db.prepare(`
            SELECT 
                COUNT(*) as totalUsers,
                SUM(CASE WHEN role = 'admin' THEN 1 ELSE 0 END) as adminCount,
                SUM(CASE WHEN role = 'user' THEN 1 ELSE 0 END) as userCount
            FROM users
        `).get()
        res.status(200).json({
            statistics: stats,
            users: users
        })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Ошибка сервера", details: error.message })
    }
})

app.delete("/api/admin/users/:id", auth, (req, res) => {
    try {
        const { id } = req.params
        if (req.user.role !== 'admin') {
            return res.status(403).json({ error: "Доступ запрещён. Требуются права администратора" })
        }
        const userToDelete = db.prepare(
            "SELECT id, username, email, role, createdAt FROM users WHERE id = ?"
        ).get(id)
        if (!userToDelete) {
            return res.status(404).json({ error: "Пользователь не найден" })
        }
        if (parseInt(id) === req.user.id) {
            return res.status(400).json({ error: "Вы не можете удалить самого себя" })
        }
        const userStats = db.prepare(`
            SELECT 
                COUNT(DISTINCT book.id) as booksCount,
                COUNT(DISTINCT reviews.id) as reviewsCount
            FROM users 
            LEFT JOIN book ON users.id = book.CreatedBy
            LEFT JOIN reviews ON users.id = reviews.userId
            WHERE users.id = ?
        `).get(id)
        db.prepare("DELETE FROM users WHERE id = ?").run(id)
        res.status(200).json({
            message: "Пользователь успешно удалён",
            deletedUser: {
                id: userToDelete.id,
                username: userToDelete.username,
                email: userToDelete.email,
                role: userToDelete.role,
                createdAt: userToDelete.createdAt,
                statistics: {
                    booksCreated: userStats.booksCount,
                    reviewsLeft: userStats.reviewsCount
                }
            }
        })
    } catch (error) {
        console.error(error)
        res.status(500).json({ error: "Ошибка сервера", details: error.message })
    }
})

app.listen(3000, () => {
    console.log("Сервер запущен на порту 3000")
})