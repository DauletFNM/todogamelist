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

// -------- Подключение к Render PostgreSQL --------
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
    cookie: { maxAge: 1000 * 60 * 60 * 24 },
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
    successRedirect: "/gamenotes",
    failureRedirect: "/login",
  })
);

// -------------------- Маршруты --------------------
app.get("/", (req, res) => {
  if (req.isAuthenticated()) res.redirect("/gamenotes");
  else res.redirect("/login");
});

app.get("/login", (req, res) => res.render("login.ejs"));
app.get("/register", (req, res) => res.render("register.ejs"));

app.get("/logout", (req, res) => {
  req.logout((err) => {
    if (err) console.log(err);
    res.redirect("/login");
  });
});

// -------------------- Страница игр --------------------
app.get("/gamenotes", async (req, res) => {
  if (!req.isAuthenticated()) return res.redirect("/login");
  try {
    const userId = req.user.id;
    const result = await db.query(
      "SELECT * FROM games WHERE user_id = $1 ORDER BY created_at DESC",
      [userId]
    );
    res.render("gamenotes.ejs", { games: result.rows });
  } catch (error) {
    console.error(error);
    res.render("gamenotes.ejs", { games: [] });
  }
});

// -------------------- Добавление игры --------------------
app.post("/add-game", async (req, res) => {
  if (!req.isAuthenticated()) return res.redirect("/login");

  const userId = req.user.id;
  const { gameName, gameStatus, gameRating, gameComment } = req.body;

  // Очистка и преобразование данных
  const rating = gameRating && gameRating.trim() !== "" ? parseInt(gameRating) : null;
  const comment = gameComment && gameComment.trim() !== "" ? gameComment.trim() : null;
  const status = gameStatus ? gameStatus.trim().toLowerCase() : null;

  try {
    await db.query(
      "INSERT INTO games (user_id, game_name, status, rating, comment) VALUES ($1, $2, $3, $4, $5)",
      [userId, gameName, status, rating, comment]
    );
    res.redirect("/gamenotes");
  } catch (error) {
    console.error("Ошибка при добавлении игры:", error);
    res.redirect("/gamenotes");
  }
});

// -------------------- Удаление игры --------------------
app.post("/delete-game", async (req, res) => {
  if (!req.isAuthenticated()) return res.redirect("/login");
  const userId = req.user.id;
  const gameId = req.body.gameId;
  try {
    await db.query("DELETE FROM games WHERE id = $1 AND user_id = $2", [gameId, userId]);
    res.redirect("/gamenotes");
  } catch (error) {
    console.error(error);
    res.redirect("/gamenotes");
  }
});

// -------------------- Регистрация --------------------
app.post("/register", async (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  try {
    const check = await db.query('SELECT * FROM "users" WHERE "email" = $1', [username]);
    if (check.rows.length > 0) return res.send("Email already exists");

    bcrypt.hash(password, saltRounds, async (err, hashedString) => {
      if (err) console.log(err);
      const result = await db.query(
        'INSERT INTO "users"(email, password) VALUES ($1, $2) RETURNING *',
        [username, hashedString]
      );
      req.login(result.rows[0], (err) => {
        if (err) console.log(err);
        res.redirect("/gamenotes");
      });
    });
  } catch (error) {
    console.log(error);
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
      const result = await db.query('SELECT * FROM "users" WHERE "email" = $1', [username]);
      if (result.rows.length === 0)
        return cb(null, false, { message: "Incorrect username or password." });

      const user = result.rows[0];
      bcrypt.compare(password, user.password, (err, isValid) => {
        if (err) return cb(err);
        if (isValid) cb(null, user);
        else cb(null, false, { message: "Incorrect username or password." });
      });
    } catch (err) {
      cb(err);
    }
  })
);

// -------------------- Passport Google --------------------
passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "https://todogamelist.onrender.com/auth/google/gamenotes",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        const result = await db.query('SELECT * FROM "users" WHERE email = $1', [profile.email]);
        if (result.rows.length === 0) {
          const newUser = await db.query(
            'INSERT INTO "users"(email, password) VALUES ($1, $2) RETURNING *',
            [profile.email, "google"]
          );
          return cb(null, newUser.rows[0]);
        } else return cb(null, result.rows[0]);
      } catch (error) {
        cb(error);
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

// -------------------- Сервер --------------------
app.listen(port, () => console.log(`✅ Server running on port ${port}`));
