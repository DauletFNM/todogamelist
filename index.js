import express from "express";
import bodyParser from "body-parser";
import PG from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import dotenv from "dotenv";
import GoogleStrategy from "passport-google-oauth2";


const app = express();

const port = process.env.PORT || 3000; 
const saltRounds = 10
dotenv.config({path: ".env"});

app.set("view engine", "ejs");
app.set("views", "./views");


const db = new PG.Client({
  connectionString: process.env.DATABASE_URL, 
  ssl: {
    rejectUnauthorized: false, 
  }
});
db.connect()

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie:{
    maxAge: 1000 * 60 * 60 * 24 
  }
}))
app.use(passport.initialize())
app.use(passport.session())

app.get('/auth/google', passport.authenticate('google', {
  scope: ['profile', 'email']
}))

app.get('/auth/google/gamenotes', passport.authenticate('google', {
  successRedirect: '/gamenotes',
  failureRedirect: '/login'
}))


app.get("/", (req, res) => {
  res.redirect("/login");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/logout", (req, res) => {
  req.logout((err) => {
    if (err) {
      console.log(err);
    }
    res.redirect("/login");
  });
});


app.get("/gamenotes", async (req, res) => {
  if (req.isAuthenticated()) {
    try {
      const userId = req.user.id; 
      const result = await db.query(
        "SELECT * FROM games WHERE user_id = $1 ORDER BY created_at DESC", 
        [userId]
      );
      const games = result.rows;

      return res.render('gamenotes.ejs', { 
        games: games
      });

    } catch (error) {
      console.error(error);
      return res.render('gamenotes.ejs', { games: [] }); 
    }
  }
  res.redirect('/login');
});

app.post("/add-game", async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.redirect('/login');
  }

  const userId = req.user.id;
  const { gameName, gameStatus } = req.body; 

  try {
    await db.query(
      "INSERT INTO games (user_id, game_name, status) VALUES ($1, $2, $3)",
      [userId, gameName, gameStatus]
    );
    res.redirect('/gamenotes'); 
  } catch (error) {
    console.error(error);
    res.redirect('/gamenotes'); 
  }
});

app.post("/delete-game", async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.redirect('/login');
  }

  const userId = req.user.id;
  const gameId = req.body.gameId; 

  try {
    await db.query(
      "DELETE FROM games WHERE id = $1 AND user_id = $2",
      [gameId, userId]
    );
    res.redirect('/gamenotes');
  } catch (error) {
    console.error(error);
    res.redirect('/gamenotes');
  }
});


app.post("/register", async (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  try {
    let check = await db.query('SELECT * FROM "users" WHERE "email" = $1', [username]);
    if (check.rows.length > 0) {
      return res.send('Email already exists')
    }
  } catch (error) {
    console.log(error)
  }

  try {
    bcrypt.hash(password, saltRounds, async (err, hashedString)=>{
      if(err){
        console.log(err)
      }
      let result = await db.query("INSERT INTO \"users\"(email, password) VALUES ($1, $2) RETURNING *", [username, hashedString])
      req.login(result.rows[0], (err) =>{
        if(err){
          console.log(err)
          return
        }
        res.redirect('/gamenotes')
      })
    })
  } catch (error) {
    console.log(error)
  }
});

app.post("/login", passport.authenticate("local", {
  successRedirect: '/gamenotes',
  failureRedirect:'/login'
}));

passport.use(new Strategy(async function verify(username, password, cb) {
  try { 
    let result = await db.query('SELECT * FROM "users" WHERE "email" = $1', [username])
    if (result.rows.length == 0) {
      return cb(null, false, { message: 'Incorrect username or password.' });
    }
    let user = result.rows[0]
    bcrypt.compare(password, user.password, async (err, isValid) =>{
      if(err){
        return cb(err)
      }
      if(isValid){
        return cb(null, user)
      } else {
        return cb(null, false, { message: 'Incorrect username or password.' })
      }
    })
  } catch (err) {
    cb(err)
  }
}));

passport.use("google", new GoogleStrategy(
  {
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: 'http://localhost:3000/auth/google/gamenotes',
    userProfileURL: 'https://www.googleapis.com/oauth2/v3/userinfo'
  }, 
  async (accessToken, refreshToken, profile, cb)=>{
    try {
      const result = await db.query('SELECT * FROM "users" WHERE email = $1', [profile.email])
      if(result.rows.length === 0){
        const newUser = await db.query('INSERT INTO "users"(email, password) VALUES ($1, $2)', [profile.email, 'google'])
        return cb(null, newUser.rows[0])
      }
      else{
        return cb(null, result.rows[0])
      }
    } catch (error) {
      return cb(error)
    }
}))

passport.serializeUser((user, cb) => {
  cb(null, user.id);
});

passport.deserializeUser(async (id, cb) => {
  try {
    const result = await db.query('SELECT * FROM "users" WHERE "id" = $1', [id]);
    const user = result.rows[0];
    cb(null, user);
  } catch (err) {
    cb(err);
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

