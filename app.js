// Import required modules and packages
import { fileURLToPath } from "url";
import fs from "fs";
import path from "path";
import multer from "multer";
import { sendVerificationEmail } from "./mailer.js";
import crypto from "crypto";
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
import morgan from "morgan";

// Initialize Express app
const app = express();
const port = 3000;
const saltRounds = 10; // Salt rounds for bcrypt
env.config(); // Load environment variables

// Set up session management

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24, // 1 day
      secure: process.env.NODE_ENV === "production", // Use HTTPS in production
      httpOnly: true, // Prevent client-side script access
    },
  })
);

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect(); // Connect to the PostgreSQL database

app.use(morgan("dev"));

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadPath = path.join(__dirname, "uploads");
    // Ensure the uploads directory exists
    fs.mkdirSync(uploadPath, { recursive: true });
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + "-" + file.originalname);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB file size limit
  fileFilter: (req, file, cb) => {
    if (!file.mimetype.startsWith("image/")) {
      return cb(new Error("Only image files are allowed!"), false);
    }
    cb(null, true);
  },
});

app.use(express.json()); // Middleware for parsing JSON data
// Middleware for parsing URL-encoded data
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    return res.status(400).send("File upload error: " + err.message);
  } else if (err) {
    return res.status(500).send("Server error: " + err.message);
  }
  next();
});

app.use((req, res, next) => {
  console.log("Logged-in User:", req.user); // This logs req.user for every request
  next(); // Pass to the next middleware
});

// Serve static files from the "public" directory
app.use(express.static("public"));

// Initialize Passport for handling authentication
app.use(passport.initialize());
app.use(passport.session()); // Use sessions with Passport

app.set("view engine", "ejs");
app.set("views", "./views"); // Assuming your views are stored in a folder named "views"

// Set up PostgreSQL connection

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.use("/uploads", express.static(path.join(__dirname, "uploads"))); // Serve uploaded files
class Blog {
  constructor({
    id,
    user_id,
    title,
    content,
    image_url,
    created_at,
    updated_at,
  }) {
    this.id = id;
    this.user_id = user_id;
    this.title = title;
    this.content = content;
    this.image_url = image_url;
    this.created_at = created_at;
    this.updated_at = updated_at;
  }

  static async getAll() {
    const result = await db.query(
      "SELECT * FROM blogs ORDER BY created_at DESC"
    );
    return result.rows.map((row) => new Blog(row));
  }

  static async getById(id) {
    try {
      const result = await db.query("SELECT * FROM blogs WHERE id = $1", [id]);
      return result.rows[0] ? new Blog(result.rows[0]) : null;
    } catch (err) {
      console.error("Database error:", err);
      throw new Error("Failed to fetch blog by ID.");
    }
  }

  static async create({ user_id, title, content, image_url }) {
    const result = await db.query(
      "INSERT INTO blogs (user_id, title, content, image_url) VALUES ($1, $2, $3, $4) RETURNING *",
      [user_id, title, content, image_url]
    );
    return new Blog(result.rows[0]);
  }

  static async update(id, { title, content }) {
    const result = await db.query(
      "UPDATE blogs SET title = $1, content = $2, updated_at = now() WHERE id = $3 RETURNING *",
      [title, content, id]
    );
    return new Blog(result.rows[0]);
  }

  static async delete(id) {
    await db.query("DELETE FROM blogs WHERE id = $1", [id]);
  }

  static async toggleLike(user_id, blog_id) {
    try {
      console.log("Toggling like for user", user_id, "on blog", blog_id);
      const result = await db.query(
        "SELECT * FROM likes WHERE user_id = $1 AND blog_id = $2",
        [user_id, blog_id]
      );

      if (result.rows.length > 0) {
        await db.query("DELETE FROM likes WHERE user_id = $1 AND blog_id = $2", [
          user_id,
          blog_id,
        ]);
      } else {
        await db.query("INSERT INTO likes (user_id, blog_id) VALUES ($1, $2)", [
          user_id,
          blog_id,
        ]);
      }

      const likeCountResult = await db.query(
        "SELECT COUNT(*) AS like_count FROM likes WHERE blog_id = $1",
        [blog_id]
      );
    return {
      likeCount: parseInt(likeCountResult.rows[0].like_count, 10),
      liked: result.rows.length === 0,
    };
    } catch (err) {
      console.error("Error toggling like", err);
      res.status(500).send("Internal Server Error");
    }
  }
}

const getAllBlogs = async (req, res) => {
  try {
    const blogs = await Blog.getAll();
    res.render("feed", { blogs: blogs.length ? blogs : [] }); // Pass blogs to the view
  } catch (error) {
    console.error("Error fetching blogs:", error);
    throw new Error("Internal server error");
  }
};

const createBlog = async (req, res) => {
  try {
    const { title, content } = req.body;

    // Validate input
    if (!title || !content) {
      console.error("Missing title or content:", { title, content });
      return res.status(400).send("Title and content are required.");
    }

    const imageUrl = req.file?.filename
      ? `/uploads/${req.file.filename}`
      : null;
    console.log("Image URL being saved:", imageUrl);
    const userId = req.user.id; // Assuming user ID is in the session
    console.log("User ID:", userId);

    await Blog.create({ user_id: userId, title, content, image_url: imageUrl });
    res.redirect("/blogs");
  } catch (error) {
    console.error("Error creating blog:", error);
    res.status(500).send("Internal Server Error");
  }
};

const getBlogById = async (req, res) => {
  try {
    const blog = await Blog.getById(req.params.id);
    if (!blog) return res.status(404).send("Blog not found");
    res.render("blogDetails", { blog });
  } catch (error) {
    console.error("Error fetching blog:", error);
    res.status(500).send("Internal Server Error");
  }
};

const updateBlog = async (req, res) => {
  try {
    const { title, content } = req.body;
    const blogId = req.params.id;
    await Blog.update(blogId, { title, content });
    res.redirect(`/blogs/${blogId}`);
  } catch (error) {
    console.error("Error updating blog:", error);
    res.status(500).send("Internal Server Error");
  }
};

const deleteBlog = async (req, res) => {
  try {
    await Blog.delete(req.params.id);
    res.redirect("/blogs");
  } catch (error) {
    console.error("Error deleting blog:", error);
    res.status(500).send("Internal Server Error");
  }
};

const toggleLikeBlog = async (req, res) => {
  try {
      console.log("Authenticated User:", req.user); // Debugging user authentication

      if (!req.user) {
          return res.status(401).json({ errorMessage: "User not authenticated" });
      }

      const user_id = req.user.id; // Correctly fetch user_id from req.user
      const blog_id = parseInt(req.params.id, 10); // Correctly fetch blog_id from route parameter

      console.log("User ID:", user_id);
      console.log("Blog ID:", blog_id);

      const result = await Blog.toggleLike(user_id, blog_id); // Pass in correct order
      res.status(200).json(result);
  } catch (error) {
      console.error("Error toggling like:", error);
      res.status(500).json({ errorMessage: "Internal server error" });
  }
};

export const addComment = async (req, res) => {
  try {
    const blogId = req.params.id;
    const { content } = req.body;
    await Blog.addComment(blogId, content, req.user.id); // Assuming user ID is in the session
    res.redirect(`/blogs/${blogId}`);
  } catch (error) {
    console.error("Error adding comment:", error);
    res.status(500).send("Internal Server Error");
  }
};

const generateVerificationCode = async (userEmail) => {
  // Generate a 6-digit verification code
  const verificationCode = Math.floor(100000 + Math.random() * 900000); // 6-digit code
  const expiryTime = new Date(Date.now() + 30 * 1000); // 30 seconds from now

  await db.query(
    // Update the user's verification code and expiry time
    "UPDATE users SET verification_code = $1, verification_code_expiry = $2 WHERE email = $3", // Update the verification code and expiry time
    [verificationCode, expiryTime, userEmail] // Parameters for the query
  );

  return verificationCode; // Return the verification code
};

app.get("/blogs", getAllBlogs); // Display all blogs
app.post(
  "/blogs",
  upload.single("image"), // Middleware for single file upload with "image" field
  async (req, res, next) => {
    console.log("Request Body:", req.body); // Log the form data
    console.log("Uploaded File:", req.file); // Log uploaded file details
    next(); // Pass control to the `createBlog` function
  },
  createBlog
);
app.get("/blogs/:id", getBlogById); // Get a specific blog by ID
app.put("/blogs/:id", updateBlog); // Update a blog
app.delete("/blogs/:id", deleteBlog); // Delete a blog
app.post("/blogs/:id/like", toggleLikeBlog); // Like a blog
app.post("/blogs/:id/comments", addComment); // Add a comment to a blog

// Home route
app.get("/", (req, res) => {
  res.render("home.ejs"); // Render the home page
});

// Login route
app.get("/login", (req, res) => {
  res.render("login.ejs"); // Render the login page
});

app.get("/verify-code", (req, res) => {
  const email = req.query.email; // Get the email from query parameters
  console.log("Email:", email); // Log the email
  if (!email) {
    return res.status(400).send("Email is required to verify the code.");
  }

  res.render("verify-code.ejs", { email }); // Pass the email to the EJS template
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
      const field = req.user.email ? "email" : "username"; // Determine the field to query
      const value = req.user.email || req.user.username; // Get the corresponding value
      const result = await db.query(`SELECT * FROM users WHERE ${field} = $1`, [
        value,
      ]);

      if (result.rows.length > 0) {
        const blogs = await Blog.getAll(); // Get all blogs

        res.render("feed.ejs", { user: result.rows[0], blogs });
      } else {
        res.status(404).send("User not found");
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
  // Register route
  console.log("Received Data: ", req.body); // Log the request body
  const usernameOrEmail = req.body.username_or_email; // Get the username or email
  const password = req.body.password; // Get the password

  // Check if the input is an email using a regex
  const isEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(usernameOrEmail); // Check if the input is an email

  try {
    // Check if the username or email already exists in the database
    const checkResult = await db.query(
      // Check if the username or email already exists
      "SELECT email FROM temp_users WHERE email = $1 UNION SELECT email FROM users WHERE email = $1", // Query to check if the username or email exists
      [usernameOrEmail] // Parameters for the query
    );

    console.log("Query Result:", checkResult.rows);

    if (checkResult.rows.length > 0) {
      console.log("User already exists", usernameOrEmail); // Log the error
      // If username or email exists, return an error message
      // If username or email exists, return an error message
      return res // Return an error message if the username or email already exists
        .status(400) // Set the status code to 400
        .json({ errorMessage: "Username or email already exists" }); // Return an error message
    }

    // Hash the password using bcrypt
    const hashedPassword = await bcrypt.hash(password, saltRounds); // Hash the password using bcrypt

    if (isEmail) {
      const verificationCode = Math.floor(100000 + Math.random() * 900000); // Generate a 6-digit verification code
      const expiryTime = new Date(Date.now() + 30 * 1000); // Set expiry time to 30 seconds
      await db.query(
        "INSERT INTO temp_users (email, password_hash, verification_code, verification_code_expiry) VALUES ($1, $2, $3, $4)", // Query to insert the user with an email, password hash, verification code, and expiry time
        [usernameOrEmail, hashedPassword, verificationCode, expiryTime]
      );

      await sendVerificationEmail(usernameOrEmail, verificationCode); // Send the verification email

      return res.status(200).json({
        // Return a success message
        message: "Verification code sent. Please verify your email to log in.", // Inform the user that a verification code has been sent
        redirectUrl: `/verify-code?email=${encodeURIComponent(
          usernameOrEmail
        )}`, // Update this to redirect to verification screen
      });
    } else {
      // Insert the user with a username and password hash
      return res
        .status(400)
        .json({ errorMessage: "Only email registrations are allowed." }); // Return an error message

      // Inform the user that registration was successful
    }
  } catch (err) {
    console.error("Error registering user:", err);
    res.status(500).json({ errorMessage: "Internal server error" });
  }
});

app.post("/resend-code", async (req, res) => {
  const { email } = req.body;

  try {
    const result = await db.query("SELECT * FROM temp_users WHERE email = $1", [
      // Check if the email exists in the database
      email,
    ]);

    if (result.rows.length === 0) {
      return res.status(400).json({ errorMessage: "Email not found." }); // Return an error if the email is not found
    }

    const verificationCode = Math.floor(100000 + Math.random() * 900000); // Generate new code
    const expiryTime = new Date(Date.now() + 30 * 1000); // Set expiry time to 30 seconds

    // Update verification code in the database
    await db.query(
      "UPDATE temp_users SET verification_code = $1, verification_code_expiry = $2 WHERE email = $3", // Update the verification code and expiry time
      [verificationCode, expiryTime, email]
    );

    // Send the new verification code
    await sendVerificationEmail(email, verificationCode); // Send the new verification code

    res.status(200).json({ message: "New verification code sent." }); // Return a success message
  } catch (err) {
    console.error("Error resending verification code:", err);
    res.status(500).json({ errorMessage: "Internal server error." }); // Return an error if there is an error resending the verification code
  }
});

app.post("/verify-code", async (req, res) => {
  const { email, code } = req.body;

  try {
    // Check if the code is valid and not expired
    const result = await db.query(
      // Check if the code is valid and not expired
      "SELECT * FROM temp_users WHERE email = $1 AND verification_code = $2 AND verification_code_expiry > NOW()", // AND verification_code_expiry > NOW() is used to check if the code is expired
      [email, code]
    );

    if (result.rows.length === 0) {
      // If the code is invalid or expired
      // Invalid or expired code
      return res
        .status(400)
        .json({ errorMessage: "Invalid or expired verification code." }); // Return an error message
    }

    const user = result.rows[0]; // Get the user from the result

    const existingUser = await db.query(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({
        errorMessage: "This email has already been verified and registered.",
      }); // Return an error if the email already exists
    }
    // Update user as verified and clear the code
    await db.query(
      "INSERT INTO users (email, password_hash, is_verified) VALUES ($1, $2, true)", // Query to insert the user with an email, password hash, verification code, and expiry time
      [user.email, user.password_hash] // Parameters for the query
    );

    await db.query("DELETE FROM temp_users WHERE email = $1", [email]); // Delete the temp_user

    // Fetch the verified user from users table
    const verifiedUser = await db.query(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );

    // Automatically log the user in using the `users` table data
    req.login(verifiedUser.rows[0], (err) => {
      if (err) {
        console.error("Error logging in user after verification:", err);
        return res.status(500).json({ errorMessage: "Failed to log in." });
      }

      return res.status(200).json({
        message: "Verification successful!",
        redirectUrl: "/feed",
      });
    });
  } catch (err) {
    console.error("Error verifying code:", err);
    res.status(500).json({ errorMessage: "Internal server error" });
  }
});

// Login route using Passport local strategy
app.post("/login", (req, res, next) => {
  // Authenticate the user using the local strategy
  passport.authenticate("local", (err, user, info) => {
    // Authenticate the user using the local strategy
    if (err) {
      // If there is an error during authentication
      console.error("Error during authentication:", err); // Log the error
      return res.status(500).json({ errorMessage: "Internal server error" }); // Return an error if there is an error during authentication
    }

    if (!user) {
      // If the user is not found
      return res.status(401).json({
        errorMessage: info.message || "Invalid username/email or password ",
      }); // Return an error if the user is not found
    }
    req.login(user, (err) => {
      // Log the user in
      if (err) {
        // If there is an error during login
        console.error("Error during login:", err); // Log the error
        return res
          .status(500)
          .json({ errorMessage: "Failed to log in the user." }); // Return an error if the user cannot be logged in
      }
      res.status(200).json({ success: true, redirectUrl: "/feed" }); // Redirect to feed on successful login
    });
  })(req, res, next); //what this does is that it calls the function that is returned by passport.authenticate
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
