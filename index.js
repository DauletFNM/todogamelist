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

// --- Подключение к PostgreSQL (Render совместимо) ---
const db = new PG.Client({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});
db.connect();

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

// -------------------- Роуты --------------------
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

// -------------------- Gamenotes --------------------
app.get("/gamenotes", async (req, res) => {
  if (!req.isAuthenticated()) return res.redirect("/login");
  try {
    const result = await db.query(
      "SELECT * FROM games WHERE user_id = $1 ORDER BY created_at DESC",
      [req.user.id]
    );
    res.render("gamenotes.ejs", { games: result.rows });
  } catch (err) {
    console.error(err);
    res.render("gamenotes.ejs", { games: [] });
  }
});

// -------------------- Добавление игры --------------------
app.post("/add-game", async (req, res) => {
  if (!req.isAuthenticated()) return res.redirect("/login");

  // проверим что реально приходит
  console.log("📥 req.body:", req.body);
  
  const { gameName, gameStatus, gameRating, gameComment } = req.body;
  const userId = req.user.id;

  const rating = gameRating ? parseInt(gameRating, 10) : null;
  const comment = gameComment ? gameComment.trim() : null;

  try {
    await db.query(
      `INSERT INTO games (user_id, game_name, status, rating, comment)
       VALUES ($1, $2, $3, $4, $5)`,
      [userId, gameName, gameStatus, rating, comment]
    );
    res.redirect("/gamenotes");
  } catch (err) {
    console.error("❌ Ошибка вставки:", err);
    res.redirect("/gamenotes");
  }
});

// -------------------- Удаление --------------------
app.post("/delete-game", async (req, res) => {
  if (!req.isAuthenticated()) return res.redirect("/login");
  try {
    await db.query("DELETE FROM games WHERE id = $1 AND user_id = $2", [
      req.body.gameId,
      req.user.id,
    ]);
    res.redirect("/gamenotes");
  } catch (err) {
    console.error(err);
    res.redirect("/gamenotes");
  }
});

// -------------------- Регистрация --------------------
app.post("/register", async (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  try {
    const check = await db.query('SELECT * FROM "users" WHERE "email" = $1', [
      username,
    ]);
    if (check.rows.length > 0) return res.send("Email already exists");

    bcrypt.hash(password, saltRounds, async (err, hashed) => {
      if (err) return console.log(err);
      const result = await db.query(
        'INSERT INTO "users"(email, password) VALUES ($1, $2) RETURNING *',
        [username, hashed]
      );
      req.login(result.rows[0], (err) => {
        if (err) console.log(err);
        res.redirect("/gamenotes");
      });
    });
  } catch (err) {
    console.log(err);
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
        return cb(null, false, { message: "Incorrect username or password." });

      const user = result.rows[0];
      bcrypt.compare(password, user.password, (err, isValid) => {
        if (err) return cb(err);
        if (isValid) cb(null, user);
        else cb(null, false);
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
        const result = await db.query('SELECT * FROM "users" WHERE email = $1', [
          profile.email,
        ]);
        if (result.rows.length === 0) {
          const newUser = await db.query(
            'INSERT INTO "users"(email, password) VALUES ($1, $2) RETURNING *',
            [profile.email, "google"]
          );
          return cb(null, newUser.rows[0]);
        }
        return cb(null, result.rows[0]);
      } catch (error) {
        cb(error);
      }
    }
  )
);

passport.serializeUser((user, cb) => cb(null, user.id));
passport.deserializeUser(async (id, cb) => {
  try {
    const result = await db.query('SELECT * FROM "users" WHERE "id" = $1', [id]);
    cb(null, result.rows[0]);
  } catch (err) {
    cb(err);
  }
});

app.listen(port, () => console.log(`✅ Server running on port ${port}`));

