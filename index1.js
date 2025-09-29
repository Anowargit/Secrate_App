// index.js
import express from "express";
import mongoose from "mongoose";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import dotenv from "dotenv";

// Load environment variables
dotenv.config();

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;

// In production, keep this secret in .env
const JWT_SECRET = process.env.JWT_SECRET || "fallback-secret-key";

// Middleware setup
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(cookieParser());
app.set("view engine", "ejs");

// Database connection
mongoose
  .connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("✅ MongoDB connected successfully"))
  .catch((err) => console.error("❌ MongoDB connection failed:", err.message));

// User schema & model
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
});

const User = mongoose.model("User", userSchema);

// Authentication middleware
function isAuthenticated(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.redirect("/login");

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.redirect("/login");
  }
}

// Routes
app.get("/", (req, res) => {
  res.redirect("/register");
});

// Registration page
app.get("/register", (req, res) => {
  res.render("register", { error: "" });
});

// Handle registration
app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;

  // Simple email validation
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.render("register", { error: "Invalid email format" });
  }

  // Password must have uppercase, lowercase, number, and at least 6 chars
  const passRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{6,}$/;
  if (!passRegex.test(password)) {
    return res.render("register", {
      error:
        "Password must be at least 6 chars and include uppercase, lowercase, and a number",
    });
  }

  try {
    // Check if email already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.render("register", { error: "Email already registered" });
    }

    // Hash password & save user
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ name, email, password: hashedPassword });
    await newUser.save();

    res.redirect("/login");
  } catch (err) {
    console.error("Error during registration:", err.message);
    res.render("register", { error: "Something went wrong. Please try again." });
  }
});

// Login page
app.get("/login", (req, res) => {
  res.render("login", { error: "" });
});

// Handle login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.render("login", { error: "User not found" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.render("login", { error: "Incorrect password" });
    }

    // Create JWT token
    const token = jwt.sign(
      { email: user.email, name: user.name },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    // Save token in cookie
    res.cookie("token", token, { httpOnly: true });
    res.redirect("/secrets");
  } catch (err) {
    console.error("Login error:", err.message);
    res.render("login", { error: "Login failed. Try again later." });
  }
});

// Protected secrets page
app.get("/secrets", isAuthenticated, (req, res) => {
  res.render("secrets", { user: req.user });
});

// Logout route
app.get("/logout", (req, res) => {
  res.clearCookie("token");
  res.redirect("/login");
});

// Start server
app.listen(PORT, () =>
  console.log(`🚀 Server running at http://localhost:${PORT}`)
);
