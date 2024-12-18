// Import required modules and packages
import axios from "axios";
import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local"; // Local strategy for username/password authentication
import session from "express-session";
import env from "dotenv";
import GoogleStrategy from "passport-google-oauth20"; // Google OAuth strategy

// Initialize Express app
const app = express();
const port = 3000;
const saltRounds = 10; // Salt rounds for bcrypt
env.config(); // Load environment variables

// Set up session management
app.use(
  session({
    secret: process.env.SESSION_SECRET, // Secret for session encryption
    resave: false,
    saveUninitialized: true,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24, // 1 day cookie expiration
    },
  })
);

app.use(express.json()); // Middleware for parsing JSON data
// Middleware for parsing URL-encoded data
app.use(bodyParser.urlencoded({ extended: true }));

// Serve static files from the "public" directory
app.use(express.static("public"));

// Initialize Passport for handling authentication
app.use(passport.initialize());
app.use(passport.session()); // Use sessions with Passport

// Set up PostgreSQL connection
const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect(); // Connect to the PostgreSQL database

const verifyEmailWithHunter = async (email) => {
  const apiKey = process.env.HUNTER_API_KEY; // Hunter API key
  const url =
    `https://api.hunter.io/v2/email-verifier?email=${email}&api_key=${apiKey}`; // Hunter API URL
  try {
    const respone = await axios.get(url); // Send a GET request to the Hunter API
    const status = response.data.data.status; // Get the status from the response

    if (status === "valid") {
      return true; // Email is valid
    } else {
      return false; // Email is invalid
    }
  } catch (error) {
    console.error("Error verifying email:", error);
    return false; // Error verifying email
  }
};
// Home route
app.get("/", (req, res) => {
  res.render("home.ejs"); // Render the home page
});

// Login route
app.get("/login", (req, res) => {
  res.render("login.ejs"); // Render the login page
});

// Register route
app.get("/register", (req, res) => {
  res.render("register.ejs"); // Render the registration page
});

// Logout route
app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/"); // Redirect to home after logout
  });
});

// Protected route - only accessible if user is authenticated
app.get("/feed", async (req, res) => {
  if (req.isAuthenticated()) {
    // Check if the user is authenticated
    try {
      // Determine whether to use email or username
      const username = req.user.email ? req.user.email : req.user.username;
      const result = req.user.email
        ? await db.query("SELECT * FROM users WHERE email = $1", [username])
        : await db.query("SELECT * FROM users WHERE username = $1", [username]);

      if (result.rows.length > 0) {
        res.render("feed.ejs", {
          user: result.rows[0].username || result.rows[0].email, // Pass the user to the feed
        });
      }
    } catch (err) {
      console.log(err);
      res.status(500).send("Error retrieving username");
    }
  } else {
    res.redirect("/login"); // Redirect to login if not authenticated
  }
});

// Google OAuth authentication routes
app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"], // Request profile and email from Google
  })
);

app.get(
  "/auth/google/feed",
  passport.authenticate("google", {
    successRedirect: "/feed", // Redirect to feed on successful login
    failureRedirect: "/login", // Redirect to login on failure
  })
);

// Registration route - handles new user sign-up
app.post("/register", async (req, res) => {
  console.log("Receieved Data: ", req.body); // Log the request body
  const usernameOrEmail = req.body.username_or_email;
  const password = req.body.password;

  console.log("Username or Email: ", usernameOrEmail); // Log the username or email
  console.log("Password: ", password); // Log the password

  // Check if the input is an email using a regex
  const isEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(usernameOrEmail); //

  if (isEmail) {
    try {
      const apiKey = process.env.HUNTER_API_KEY; // Hunter API key
      const hunterResponse = await axios.get(
        `https://api.hunter.io/v2/email-verifier?email=${usernameOrEmail}&api_key=${apiKey}`
      ); // Send a GET request to the Hunter API
  
      console.log("Hunter Response:", hunterResponse.data); // Log the response from Hunter API
      const verificationStatus = hunterResponse.data.data.status; // Get the status from the response
  
      if (verificationStatus !== "valid" && verificationStatus !== "accept_all") {
        return res.status(400).json({errorMessage: "Invalid email address"}); // Return an error if the email is invalid
      }
    } catch (err) {
      console.error("Error verifying email:", err);
      return res.status(500).json({errorMessage: "Email verification failed"}); // Return an error if email verification fails
  }
}

try{
    // Check if the username or email already exists in the database
    const checkResult = await db.query(
      "SELECT * FROM users WHERE email = $1 OR username = $2",
      [usernameOrEmail, usernameOrEmail]
    );

    if (checkResult.rows.length > 0) {
      // If username or email exists, render the registration page with an error message
      return res.status(400).json({errorMessage: "Username or email already exists"});
    }

    // Hash the password using bcrypt
    try
    {
      const hashedPassword = await bcrypt.hash(password, saltRounds);

      // Insert user based on whether the input is email or username
      const result = isEmail
        ? await db.query(
            "INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING *",
            [usernameOrEmail, hashedPassword]
          )
        : await db.query(
            "INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING *",
            [usernameOrEmail, hashedPassword]
          );

      // Get the inserted user and log them in using Passport
      const user = result.rows[0];
      req.login(user, (err) => {
        if (err) {
          return res.status(500).send("Internal server error");
        }
        res.status(200).json({success: true, redirectUrl: "/feed"})
      });
    }
    catch (err) {
      console.error("Error hashing password:", err);
      res.status(500).send("Internal server error");
    }

  } catch (err) {
    console.error("Error registering user:", err);
    res.status(500).json({errorMessage: "Internal server error"});
  }
})
// Login route using Passport local strategy
app.post("/login",(req, res, next) => { // Authenticate the user using the local strategy
  passport.authenticate("local", (err, user, info) => { // Authenticate the user using the local strategy
    if(err) // If there is an error during authentication
    {
      console.error("Error during authentication:", err); // Log the error
      return res.status(500).json({errorMessage: "Internal server error"}) // Return an error if there is an error during authentication
    }

    if (!user) // If the user is not found
    {
      return res.status(401).json({ errorMessage: info.message || "Invalid username/email or password " }); // Return an error if the user is not found
      }
      req.login(user, (err) => { // Log the user in
        if (err) { // If there is an error during login
          console.error("Error during login:", err); // Log the error
          return res.status(500).json({errorMessage: "Failed to log in the user."}) // Return an error if the user cannot be logged in
        }
        res.status(200).json({success: true, redirectUrl: "/feed"}) // Redirect to feed on successful login
      });
    }) (req, res, next); //what this does is that it calls the function that is returned by passport.authenticate
  });


// Local authentication strategy (username or email and password)
passport.use(
  "local",
  new Strategy(
    {
      usernameField: "username_or_email", // Use username or email field for login
      passwordField: "password", // Password field
    },
    async function verify(usernameOrEmail, password, cb) {
      try {
        // Check if the input is an email using a regex
        const isEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(usernameOrEmail);

        // Query the database for the user by email or username
        const query = isEmail
          ? "SELECT * FROM users WHERE email = $1"
          : "SELECT * FROM users WHERE username = $1";
        const values = [usernameOrEmail];
        const result = await db.query(query, values);

        if (result.rows.length === 0) {
          // User not found
          return cb(null, false, {
            message: "User with this email or username does not exist.",
          });
        }

        const user = result.rows[0];
        const storedPassword = user.password_hash;

        // Compare the password provided with the hashed password
        const isValidPassword = await bcrypt.compare(password, storedPassword);
        if (!isValidPassword) {
          // Password mismatch
          return cb(null, false, { message: "Incorrect password." });
        }

        // If the password is valid, log the user in
        return cb(null, user);
      } catch (err) {
        console.error("Error in local strategy:", err);
        return cb(err); // Pass the error to the callback
      }
    }
  )
);


// Google OAuth strategy
passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID, // Google OAuth client ID
      clientSecret: process.env.GOOGLE_CLIENT_SECRET, // Google OAuth client secret
      callbackURL: "http://localhost:3000/auth/google/feed", // Redirect URL after Google login
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo", // URL to fetch Google profile
    },
    async (accessToken, refreshToken, profile, cb) => {
      //access token is used to access the user's data
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
