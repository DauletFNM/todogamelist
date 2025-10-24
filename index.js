import express from "express";
import bodyParser from "body-parser";
import PG from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import dotenv from "dotenv";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import crypto from "crypto";
import { Resend } from "resend";

dotenv.config({ path: ".env" });

const app = express();
const port = process.env.PORT || 3000;
const saltRounds = 10;

// -------- Подключение PostgreSQL (Render) --------
const db = new PG.Client({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});
db.connect();

// -------- Инициализация Resend --------
const resend = new Resend(process.env.RESEND_API_KEY);

// -------- Настройки Express --------
app.set("view engine", "ejs");
app.set("views", "./views");

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(
  session({
    secret: process.env.SESSION_SECRET || "secret",
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 1000 * 60 * 60 * 24 }, // 1 день
  })
);

app.use(passport.initialize());
app.use(passport.session());

// -------------------- Google OAuth --------------------
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get(
  "/auth/google/gamenotes",
  passport.authenticate("google", {
    failureRedirect: "/login",
  }),
  (req, res) => {
    console.log("✅ Google вход успешен для:", req.user?.email);
    res.redirect("/gamenotes");
  }
);

// -------------------- Основные страницы --------------------
app.get("/", (req, res) => {
  if (req.isAuthenticated()) res.redirect("/gamenotes");
  else res.redirect("/login");
});

app.get("/login", (req, res) => res.render("login.ejs"));
app.get("/register", (req, res) => res.render("register.ejs", { error: null }));
app.get("/forgot-password", (req, res) => res.render("forgotpassword.ejs"));
app.get("/logout", (req, res) => {
  req.logout((err) => {
    if (err) console.log(err);
    res.redirect("/login");
  });
});

// ==================== FORGOT / RESET PASSWORD ====================
app.post("/forgot-password", async (req, res) => {
  const { email } = req.body;

  try {
    // 1️⃣ Проверяем, есть ли пользователь
    const result = await db.query("SELECT * FROM users WHERE email = $1", [email]);
    if (result.rows.length === 0) {
      return res.status(404).send("Email не найден");
    }

    // 2️⃣ Генерируем токен и сохраняем
    const token = crypto.randomBytes(20).toString("hex");
    await db.query("UPDATE users SET reset_token = $1 WHERE email = $2", [token, email]);

    // 3️⃣ Отправляем письмо через Resend
    await resend.emails.send({
      from: "onboarding@resend.dev", // можно заменить после верификации домена
      to: email,
      subject: "Восстановление пароля",
      html: `
        <p>Здравствуйте!</p>
        <p>Чтобы восстановить пароль, нажмите на ссылку ниже:</p>
        <p><a href="https://todogamelist.onrender.com/reset-password/${token}">
          Восстановить пароль
        </a></p>
        <p>Если вы не запрашивали сброс, просто проигнорируйте это письмо.</p>
      `,
    });

    console.log(`📩 Письмо отправлено на ${email}`);
    res.send("✅ Проверьте вашу почту для восстановления пароля");
  } catch (error) {
    console.error("❌ Ошибка при отправке письма:", error);
    res.status(500).send("Ошибка при отправке письма");
  }
});

app.get("/reset-password/:token", async (req, res) => {
  const { token } = req.params;
  const result = await db.query("SELECT * FROM users WHERE reset_token = $1", [token]);

  if (result.rows.length === 0) {
    return res.status(404).send("Неверный или устаревший токен");
  }

  res.render("resetpassword.ejs", { token });
});

app.post("/reset-password", async (req, res) => {
  const { token, password } = req.body;

  const result = await db.query("SELECT * FROM users WHERE reset_token = $1", [token]);
  if (result.rows.length === 0) {
    return res.status(404).send("Неверный или устаревший токен");
  }

  const hashedPassword = await bcrypt.hash(password, saltRounds);
  await db.query("UPDATE users SET password = $1, reset_token = NULL WHERE reset_token = $2", [hashedPassword, token]);

  res.send("✅ Пароль успешно обновлён. Теперь вы можете войти.");
});

// -------------------- Страница с играми --------------------
app.get("/gamenotes", async (req, res) => {
  if (!req.isAuthenticated()) return res.redirect("/login");

  try {
    const result = await db.query(
      "SELECT * FROM games WHERE user_id = $1 ORDER BY created_at DESC",
      [req.user.id]
    );
    res.render("gamenotes.ejs", { games: result.rows });
  } catch (error) {
    console.error("❌ Ошибка при загрузке игр:", error);
    res.render("gamenotes.ejs", { games: [] });
  }
});

// -------------------- Добавление игры --------------------
app.post("/add-game", async (req, res) => {
  if (!req.isAuthenticated()) return res.redirect("/login");

  const { gameName, gameStatus, gameRating, gameComment } = req.body;
  const userId = req.user.id;
  const rating = gameRating?.trim() ? parseInt(gameRating, 10) : null;
  const comment = gameComment?.trim() || null;

  try {
    await db.query(
      "INSERT INTO games (user_id, game_name, status, rating, comment) VALUES ($1, $2, $3, $4, $5)",
      [userId, gameName, gameStatus, rating, comment]
    );
    res.redirect("/gamenotes");
  } catch (error) {
    console.error("❌ Ошибка при добавлении игры:", error);
    res.redirect("/gamenotes");
  }
});

// -------------------- Удаление игры --------------------
app.post("/delete-game", async (req, res) => {
  if (!req.isAuthenticated()) return res.redirect("/login");

  try {
    await db.query("DELETE FROM games WHERE id = $1 AND user_id = $2", [
      req.body.gameId,
      req.user.id,
    ]);
    res.redirect("/gamenotes");
  } catch (error) {
    console.error("❌ Ошибка при удалении игры:", error);
    res.redirect("/gamenotes");
  }
});

// -------------------- Регистрация --------------------
app.post("/register", async (req, res) => {
  const { username, password, confirmPassword } = req.body;

  if (password !== confirmPassword) {
    return res.send("❌ Пароли не совпадают");
  }

  try {
    const checkUser = await db.query('SELECT * FROM "users" WHERE email = $1', [username]);
    if (checkUser.rows.length > 0) {
      return res.send("❌ Такой пользователь уже существует");
    }

    const hashed = await bcrypt.hash(password, saltRounds);
    const result = await db.query(
      'INSERT INTO "users"(email, password) VALUES ($1, $2) RETURNING *',
      [username, hashed]
    );
    const user = result.rows[0];

    req.login(user, (err) => {
      if (err) return res.redirect("/login");
      res.redirect("/gamenotes");
    });
  } catch (err) {
    console.error("Ошибка регистрации:", err);
    res.redirect("/register");
  }
});

// -------------------- Логин --------------------
app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/gamenotes",
    failureRedirect: "/login",
  })
);

// -------------------- Passport Local --------------------
passport.use(
  new Strategy(async (username, password, cb) => {
    try {
      const result = await db.query('SELECT * FROM "users" WHERE "email" = $1', [username]);
      if (result.rows.length === 0)
        return cb(null, false, { message: "Неверный логин или пароль" });

      const user = result.rows[0];
      const isValid = await bcrypt.compare(password, user.password);

      return isValid ? cb(null, user) : cb(null, false, { message: "Неверный логин или пароль" });
    } catch (err) {
      cb(err);
    }
  })
);

// -------------------- Passport Google --------------------
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "https://todogamelist.onrender.com/auth/google/gamenotes",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        const email = profile.emails?.[0]?.value;
        if (!email) return cb(new Error("Google не вернул email"));

        const result = await db.query('SELECT * FROM "users" WHERE email = $1', [email]);
        let user;

        if (result.rows.length === 0) {
          const insert = await db.query(
            'INSERT INTO "users"(email, password) VALUES ($1, $2) RETURNING *',
            [email, "google"]
          );
          user = insert.rows[0];
        } else {
          user = result.rows[0];
        }

        return cb(null, user);
      } catch (err) {
        cb(err);
      }
    }
  )
);

// -------------------- Passport сериализация --------------------
passport.serializeUser((user, cb) => cb(null, user.id));
passport.deserializeUser(async (id, cb) => {
  try {
    const result = await db.query('SELECT * FROM "users" WHERE "id" = $1', [id]);
    cb(null, result.rows[0]);
  } catch (err) {
    cb(err);
  }
});

// -------------------- Глобальный обработчик ошибок --------------------
app.use((err, req, res, next) => {
  console.error("❌ Ошибка на сервере:", err.stack || err);
  res.status(500).send("Internal Server Error");
});

// -------------------- Запуск --------------------
app.listen(port, () => console.log(`✅ Server running on port ${port}`));
