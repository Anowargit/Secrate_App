import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import mongoose from "mongoose";
import dotenv from "dotenv";
dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = "myverysecuresecretkey";

app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(cookieParser());
app.set("view engine", "ejs");

mongoose
  .connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => console.error("❌ MongoDB connection error:", err));

const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
});
const User = mongoose.model("User", userSchema);
function isAuthenticated(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.redirect("/login");
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.redirect("/login");
  }
}

app.get("/", (req, res) => res.redirect("/register"));
app.get("/register", (req, res) => res.render("register", { error: "" }));
app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email))
    return res.render("register", { error: "Invalid email format" });
  const passRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{6,}$/;
  if (!passRegex.test(password))
    return res.render("register", { error: "Password must include lowercase, uppercase, number and 6+ chars" });
  const existingUser = await User.findOne({ email });
  if (existingUser) return res.render("register", { error: "Email already registered" });
  const hashedPass = await bcrypt.hash(password, 10);
  const newUser = new User({ name, email, password: hashedPass });
  await newUser.save();
  res.redirect("/login");
});

app.get("/login", (req, res) => res.render("login", { error: "" }));
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.render("login", { error: "User not found" });
  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.render("login", { error: "Incorrect password" });
  const token = jwt.sign({ email: user.email, name: user.name }, JWT_SECRET, {
    expiresIn: "1h",
  });

  res.cookie("token", token, { httpOnly: true, secure: false });
  res.redirect("/secrets");
});

app.get("/secrets", isAuthenticated, (req, res) => {
  res.render("secrets", { user: req.user });
});
app.get("/logout", (req, res) => {
  res.clearCookie("token");
  res.redirect("/login");
});
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
