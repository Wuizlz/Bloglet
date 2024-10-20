// Import required modules and packages
import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";  // Local strategy for username/password authentication
import session from "express-session";
import env from "dotenv";
import GoogleStrategy from "passport-google-oauth20";  // Google OAuth strategy

// Initialize Express app
const app = express();
const port = 3000;
const saltRounds = 10;  // Salt rounds for bcrypt
env.config();  // Load environment variables

// Set up session management
app.use(
  session({
    secret: process.env.SESSION_SECRET,  // Secret for session encryption
    resave: false,
    saveUninitialized: true,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24,  // 1 day cookie expiration
    },
  })
);

// Middleware for parsing URL-encoded data
app.use(bodyParser.urlencoded({ extended: true }));

// Serve static files from the "public" directory
app.use(express.static("public"));

// Initialize Passport for handling authentication
app.use(passport.initialize());
app.use(passport.session());  // Use sessions with Passport

// Set up PostgreSQL connection
const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect();  // Connect to the PostgreSQL database

// Home route
app.get("/", (req, res) => {
  res.render("home.ejs");  // Render the home page
});

// Login route
app.get("/login", (req, res) => {
  res.render("login.ejs");  // Render the login page
});

// Register route
app.get("/register", (req, res) => {
  res.render("register.ejs");  // Render the registration page
});

// Logout route
app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");  // Redirect to home after logout
  });
});

// Protected route - only accessible if user is authenticated
app.get("/feed", async (req, res) => {
  if (req.isAuthenticated()) {  // Check if the user is authenticated
    try {
      // Determine whether to use email or username
      const username = req.user.email ? req.user.email : req.user.username;
      const result = req.user.email
        ? await db.query("SELECT * FROM users WHERE email = $1", [username])
        : await db.query("SELECT * FROM users WHERE username = $1", [username]);

      if (result.rows.length > 0) {
        res.render("feed.ejs", {
          user: result.rows[0].username || result.rows[0].email,  // Pass the user to the feed
        });
      }
    } catch (err) {
      console.log(err);
      res.status(500).send("Error retrieving username");
    }
  } else {
    res.redirect("/login");  // Redirect to login if not authenticated
  }
});

// Google OAuth authentication routes
app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],  // Request profile and email from Google
  })
);

app.get(
  "/auth/google/feed",
  passport.authenticate("google", {
    successRedirect: "/feed",  // Redirect to feed on successful login
    failureRedirect: "/login",  // Redirect to login on failure
  })
);

// Registration route - handles new user sign-up
app.post("/register", async (req, res) => {
  const usernameOrEmail = req.body.username_or_email;
  const password = req.body.password;

  // Check if the input is an email using a regex
  const isEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(usernameOrEmail);

  try {
    // Check if the username or email already exists in the database
    const checkResult = await db.query(
      "SELECT * FROM users WHERE email = $1 OR username = $2",
      [usernameOrEmail, usernameOrEmail]
    );

    if (checkResult.rows.length > 0) {
      // If username or email exists, render the registration page with an error message
      return res.render("register.ejs", { errorMessage: "Username or Email is already taken" });
    }

    // Hash the password using bcrypt
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

      // Get the inserted user and log them in using Passport
      const user = result.rows[0];
      req.login(user, (err) => {
        if (err) {
          console.error("Login error:", err);
          return res.status(500).send("Internal server error");
        }
        console.log("Registration Successful");
        res.redirect("/feed");  // Redirect to feed after successful registration
      });
    });
  } catch (err) {
    console.error("Database error:", err);
    res.status(500).send("Internal server error");
  }
});

// Login route using Passport local strategy
app.post( "/login",
  passport.authenticate("local", {
    successRedirect: "/feed",  // Redirect to feed on successful login
    failureRedirect: "/login",  // Redirect to login on failure
  })
);

// Local authentication strategy (username or email and password)
passport.use(
  "local",
  new Strategy({
    usernameField: "username_or_email",  // Use username or email field for login
    passwordField: "password"  // Password field
  }, async function verify(usernameOrEmail, password, cb) {
    try {
      // Check if the input is an email using a regex
      const isEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(usernameOrEmail);

      // Query the database for the user by email or username
      const result = isEmail
      ? await db.query("SELECT * FROM users WHERE email = $1", [usernameOrEmail])
      : await db.query("SELECT * FROM users WHERE username = $1", [usernameOrEmail]);

      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedPassword = user.password_hash;

        // Compare the password provided with the hashed password
        bcrypt.compare(password, storedPassword, (err, valid) => {
          if (err) {
            console.error("Error comparing passwords:", err);
            return cb(err);
          } else {
            if (valid) {
              // If the password is valid, log the user in
              return cb(null, user);
            } else {
              // Password mismatch
              return cb(null, false);
            }
          }
        });
      } else {
        // User not found
        return cb(null, false, { message: "Incorrect username or password." });
      }
    } catch (err) {
      console.log(err);
    }
  })
);

// Google OAuth strategy
passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,  // Google OAuth client ID
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,  // Google OAuth client secret
      callbackURL: "http://localhost:3000/auth/google/feed",  // Redirect URL after Google login
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",  // URL to fetch Google profile
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
        // Query the database for the Google user by Google ID or email
        const result = await db.query(
          "SELECT * FROM users WHERE google_id = $1 OR email = $2",
          [profile.id, profile.emails[0].value]
        );

        if (result.rows.length === 0) {
          // If the user is not found, insert them into the database
          const newUser = await db.query(
            "INSERT INTO users (email, google_id) VALUES ($1, $2) RETURNING *",
            [profile.emails[0].value, profile.id]
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

// Serialize user information into session
passport.serializeUser((user, cb) => {
  cb(null, user);
});

// Deserialize user information from session
passport.deserializeUser((user, cb) => {
  cb(null, user);
});

// Start the server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
