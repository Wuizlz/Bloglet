import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import session from "express-session";
import env from "dotenv";
import GoogleStrategy from "passport-google-oauth20";

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24,
    },
  })
);

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect();

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/logout", (req, res,) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.get("/feed", async (req, res) => {
  if (req.isAuthenticated()) {
    try {
      const username = req.user.email ? req.user.email : req.user.username;
      const result = req.user.email
        ? await db.query("SELECT * FROM users WHERE email = $1", [username])
        : await db.query("SELECT * FROM users WHERE username = $1", [username]);

      if (result.rows.length > 0) {
        res.render("feed.ejs", {
          user: result.rows[0].username || result.rows[0].email,
        });
      }
    } catch (err) {
      console.log(err);
      console.error("Database query failed", err);
      res.status(500).send("Error retrieving username");
    }
  } else {
    res.redirect("/login");
  }
});

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get(
  "/auth/google/feed",
  passport.authenticate("google", {
    successRedirect: "/feed",
    failureRedirect: "/login",
  })
);

app.post("/register", async (req, res) => {
  const usernameOrEmail = req.body.username_or_email;
  const password = req.body.password;

  // Check to see if it's an email
  const isEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(usernameOrEmail);

  try {
    // Check if the username or email already exists
    const checkResult = await db.query(
      "SELECT * FROM users WHERE email = $1 OR username = $2",
      [usernameOrEmail, usernameOrEmail]
    );

    if (checkResult.rows.length > 0) {
      // If username or email exists, redirect to login with a message
      return res.render("register.ejs", {errorMessage: "Username or Email is already taken"})
    }

    // Hash the password
    bcrypt.hash(password, saltRounds, async (err, hash) => {
      if (err) {
        console.error("Error hashing password:", err);
        return res.status(500).send("Internal server error");
      }

      // Insert user based on whether the input is email or username
      const result = isEmail
        ? await db.query(
            "INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING *",
            [usernameOrEmail, hash]
          )
        : await db.query(
            "INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING *",
            [usernameOrEmail, hash]
          );

      // Get the inserted user and log them in
      const user = result.rows[0];
      req.login(user, (err) => {
        if (err) {
          console.error("Login error:", err);
          return res.status(500).send("Internal server error");
        }
        console.log("Registration Successful");
        res.redirect("/feed");
      });
    });
  } catch (err) {
    console.error("Database error:", err);
    res.status(500).send("Internal server error");
  }
});


app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/feed",
    failureRedirect: "/login",
  })
);

passport.use(
  "local",
  new Strategy({
    usernameField: "username_or_email",
    passwordField: "password"
  }, async function verify(usernameOrEmail, password, cb) {
    try {
      const isEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(usernameOrEmail);

      const result = isEmail
      ?await db.query("SELECT * FROM users WHERE email = $1 ", [
        username_or_email])
        : await db.query("SELECT * FROM users WHERE username = $1", [usernameOrEmail]);

      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedPassword = user.password_hash;

        bcrypt.compare(password, storedPassword, (err, valid) => {
          if (err) {
            console.error("Error comparing passwords:", err);
            return cb(err);
          } else {
            if (valid) {
              //if valid log them in
              return cb(null, user);
            } else {
              //password mismatch
              return cb(null, false);
            }
          }
        });
      } else {
        //user not found with provided email or username
        return cb(null, false, { message: "Incorrect username or password." });
      }
    } catch (err) {
      console.log(err);
    }
  })
);

passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/feed",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        const email =
          profile.emails && profile.emails[0] ? profile.emails[0].value : null;
        if (!email) {
          return cb(null, false, {
            message: "No email associated with this Google account.",
          });
        }

        console.log(profile);
        // Query the database using the user's Google ID or email
        const result = await db.query(
          "SELECT * FROM users WHERE google_id = $1 OR email = $2",
          [profile.id, profile.emails[0].value]
        );

        if (result.rows.length === 0) {
          // Insert new user if not found
          const newUser = await db.query(
            "INSERT INTO users (email, google_id) VALUES ($1, $2) RETURNING *",
            [profile.emails[0].value, profile.id] // Storing email and Google ID
          );
          return cb(null, newUser.rows[0]);
        } else {
          // User exists, return the user
          return cb(null, result.rows[0]);
        }
      } catch (err) {
        return cb(err);
      }
    }
  )
);

passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
});
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
