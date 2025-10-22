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
        // ✅ Получаем email независимо от структуры профиля
        const email = profile.emails?.[0]?.value || profile.email;

        if (!email) {
          console.error("❌ Google не вернул email! Полный профиль:", profile);
          return cb(new Error("Не удалось получить email от Google"));
        }

        // Проверяем, есть ли пользователь
        const existingUser = await db.query(
          'SELECT * FROM "users" WHERE email = $1',
          [email]
        );

        let user;

        if (existingUser.rows.length === 0) {
          console.log(`🟢 Новый пользователь Google: ${email}`);
          const inserted = await db.query(
            'INSERT INTO "users"(email, password) VALUES ($1, $2) RETURNING *',
            [email, "google"]
          );
          user = inserted.rows[0];
        } else {
          user = existingUser.rows[0];
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
