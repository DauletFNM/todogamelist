import express from "express";
import bodyParser from "body-parser";
import PG from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import dotenv from "dotenv";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";

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

// -------- Настройки Express --------
app.set("view engine", "ejs");
app.set("views", "./views");

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(
  session({
    secret: process.env.SESSION_SECRET,
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

// -------------------- Роуты --------------------
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
    const result = await db.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(404).send("Email not found");
    }

    const token = crypto.randomBytes(20).toString("hex");
    await db.query("UPDATE users SET reset_token = $1 WHERE email = $2", [token, email]);

    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.GMAIL_USER,     
        pass: process.env.GMAIL_PASS,      
      },
    });

    const mailOptions = {
      from: process.env.GMAIL_USER,
      to: email,
      subject: "Восстановление пароля",
      text: `Воидите по этой ссылке чтобы восстановить пароль: https://todogamelist.onrender.com/reset-password/${token}`,
    };

    await transporter.sendMail(mailOptions);
    res.send("Проверьте вашу почту для восстановления пароля");
  } catch (error) {
    console.error(error);
    res.status(500).send("Ошибка при отправке письма");
  }
});

app.get("/reset-password/:token", async (req, res) => {
  const { token } = req.params;
  const result = await db.query("SELECT * FROM users WHERE reset_token = $1", [token]);

  if (result.rows.length === 0) {
    return res.status(404).send("Invalid or expired token");
  }

  res.render("resetpassword.ejs", { token });
});

app.post("/reset-password", async (req, res) => {
  const { token, password } = req.body;

  const result = await db.query("SELECT * FROM users WHERE reset_token = $1", [token]);
  if (result.rows.length === 0) {
    return res.status(404).send("Invalid or expired token");
  }

  const hashedPassword = await bcrypt.hash(password, saltRounds);
  await db.query("UPDATE users SET password = $1, reset_token = NULL WHERE reset_token = $2", [hashedPassword, token]);

  res.send("Пароль успешно обновлён");
});

// -------------------- Главная (все игры) --------------------
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

  console.log("📩 req.body:", req.body);

  const { gameName, gameStatus, gameRating, gameComment } = req.body;
  const userId = req.user.id;

  const rating =
    gameRating && gameRating.trim() !== "" ? parseInt(gameRating, 10) : null;
  const comment =
    gameComment && gameComment.trim() !== "" ? gameComment.trim() : null;

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

  // 1️⃣ Проверяем, совпадают ли пароли
  if (password !== confirmPassword) {
    return res.send("❌ Пароли не совпадают");
  }

  try {
    // 2️⃣ Проверяем, есть ли пользователь с таким email
    const checkUser = await db.query('SELECT * FROM "users" WHERE email = $1', [username]);
    if (checkUser.rows.length > 0) {
      return res.send("❌ Такой пользователь уже существует");
    }

    // 3️⃣ Хешируем пароль
    const hashed = await bcrypt.hash(password, saltRounds);

    // 4️⃣ Создаём нового пользователя
    const result = await db.query(
      'INSERT INTO "users"(email, password) VALUES ($1, $2) RETURNING *',
      [username, hashed]
    );
    const user = result.rows[0];

    // 5️⃣ Логиним пользователя и редиректим
    req.login(user, (err) => {
      if (err) {
        console.log("Ошибка логина:", err);
        return res.redirect("/login");
      }
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
  new Strategy(async function verify(username, password, cb) {
    try {
      const result = await db.query('SELECT * FROM "users" WHERE "email" = $1', [
        username,
      ]);
      if (result.rows.length === 0)
        return cb(null, false, { message: "Неверный логин или пароль" });

      const user = result.rows[0];
      const isValid = await bcrypt.compare(password, user.password);

      if (isValid) return cb(null, user);
      else return cb(null, false, { message: "Неверный логин или пароль" });
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
        // ✅ Google иногда возвращает email в массиве
        const email = profile.emails?.[0]?.value || profile.email;

        if (!email) {
          console.error("❌ Google не вернул email:", profile);
          return cb(new Error("Google не вернул email"));
        }

        const result = await db.query('SELECT * FROM "users" WHERE email = $1', [
          email,
        ]);

        let user;

        if (result.rows.length === 0) {
          console.log(`🟢 Новый пользователь Google: ${email}`);
          const insert = await db.query(
            'INSERT INTO "users"(email, password) VALUES ($1, $2) RETURNING *',
            [email, "google"]
          );
          user = insert.rows[0];
        } else {
          user = result.rows[0];
          console.log(`✅ Google вход успешен для: ${user.email}`);
        }

        return cb(null, user);
      } catch (err) {
        console.error("❌ Ошибка в Google стратегии:", err);
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



