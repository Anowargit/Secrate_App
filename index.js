const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const bodyParser = require("body-parser");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = "mysecretkey";

app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static("public"));
app.set("view engine", "ejs");

mongoose.connect("mongodb://127.0.0.1:27017/secretsDB");

const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String
});

const User = mongoose.model("User", userSchema);

function authMiddleware(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.redirect("/");
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.redirect("/");
  }
}

app.get("/", (req, res) => res.render("index"));
app.get("/register", (req, res) => res.render("register"));
app.get("/secrets", authMiddleware, (req, res) => res.render("secrets", { user: req.user }));

app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) return res.send("Invalid Email Format");

  const passRegex = /^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,15}$/;
  if (!passRegex.test(password)) return res.send("password not meet the minimum requirements");

  const hashedPass = await bcrypt.hash(password, 10);
  await User.create({ name, email, password: hashedPass });
  res.redirect("/");
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });
  if (!user) return res.send("User not found");

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.send("Invalid Credentials");

  const token = jwt.sign({ name: user.name, email: user.email }, JWT_SECRET, { expiresIn: "1h" });
  res.cookie("token", token, { httpOnly: true, secure: true });
  res.redirect("/secrets");
});

app.get("/logout", (req, res) => {
  res.clearCookie("token");
  res.redirect("/");
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
