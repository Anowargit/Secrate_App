import express from "express";
import mongoose from "mongoose";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import dotenv from "dotenv";


const app = express();
const port = process.env.PORT || 3000;

const secretKey = process.env.JWT_SECRET || "my-secret-key";

app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(cookieParser());
app.set("view engine", "ejs");

mongoose.connect("mongodb://localhost:27017/secrets-app", {
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
})
.then(() => console.log("Connected to MongoDB"))
.catch(err => console.log("MongoDB connection error:", err));

const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String
});

const User = mongoose.model("User", userSchema);

function checkIfLoggedIn(req, res, next) {
  const token = req.cookies.token;
  
  if (!token) {
    return res.redirect("/login");
  }
  
  try {
    const userData = jwt.verify(token, secretKey);
    req.user = userData;
    next();
  } catch (err) {
    res.redirect("/login");
  }
}


app.get("/", (req, res) => {
  res.redirect("/register");
});

app.get("/register", (req, res) => {
  res.render("register", { error: null });
});

app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;
  
  if (!email.includes("@") || !email.includes(".")) {
    return res.render("register", { error: "Email doesn't look right" });
  }
  
  if (password.length < 6) {
    return res.render("register", { error: "Password should be at least 6 characters" });
  }
  
  try {
    const existingUser = await User.findOne({ email: email });
    if (existingUser) {
      return res.render("register", { error: "This email is already registered" });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const newUser = new User({
      name: name,
      email: email,
      password: hashedPassword
    });
    
    await newUser.save();
    res.redirect("/login");
    
  } catch (err) {
    console.log("Error:", err);
    res.render("register", { error: "Something went wrong. Try again." });
  }
});

app.get("/login", (req, res) => {
  res.render("login", { error: null });
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  
  try {
    const user = await User.findOne({ email: email });
    
    if (!user) {
      return res.render("login", { error: "User not found" });
    }
    
    const isPasswordCorrect = await bcrypt.compare(password, user.password);
    
    if (!isPasswordCorrect) {
      return res.render("login", { error: "Wrong password" });
    }
    
    const token = jwt.sign(
      { email: user.email, name: user.name },
      secretKey,
      { expiresIn: "1h" }
    );
    
    res.cookie("token", token, { httpOnly: true });
    res.redirect("/secrets");
    
  } catch (err) {
    console.log("Login error:", err);
    res.render("login", { error: "Login failed" });
  }
});

app.get("/secrets", checkIfLoggedIn, (req, res) => {
  res.render("secrets", { user: req.user });
});

app.get("/logout", (req, res) => {
  res.clearCookie("token");
  res.redirect("/login");
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});