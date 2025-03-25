import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import session from "express-session";
import env from "dotenv";
import shortid from "shortid";
import pool from "./db/pool.js";

const app = express();
const saltRound = 10;
env.config();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(
  session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: true,
  })
);

app.use(passport.initialize());
app.use(passport.session());

// Routes
app.get("/dashboard", async (req, res) => {
  try {
    if (!req.isAuthenticated()) return res.redirect("/login");

    const id = req.user.id;
    const secret = await pool.query(
      "SELECT short_key, original_url, user_id FROM urls WHERE user_id = $1",
      [id]
    );

    res.render("dashboard.ejs", { secret: secret.rows });
  } catch (error) {
    console.error("Error fetching dashboard:", error);
    res.status(500).send("Internal Server Error - DB issue");
  }
});

app.get("/", (req, res) => res.render("home.ejs"));
app.get("/register", (req, res) => res.render("register.ejs"));
app.get("/login", (req, res) => res.render("login.ejs"));

app.post("/delete", async (req, res) => {
  try {
    const del = req.body.id;
    await pool.query("DELETE FROM urls WHERE short_key = $1", [del]);
    res.redirect("/dashboard");
  } catch (error) {
    console.error("Error deleting URL:", error);
    res.status(500).send("Internal Server Error");
  }
});

app.post("/register", async (req, res) => {
  try {
    const email = req.body.username;
    const password = req.body.password;

    const result = await pool.query("SELECT * FROM users WHERE email=$1", [email]);

    if (result.rows.length > 0) {
      res.send("You are already registered. Try logging in.");
    } else {
      const hash = await bcrypt.hash(password, saltRound);
      await pool.query(
        "INSERT INTO users (email, password) VALUES ($1, $2)",
        [email, hash]
      );
      res.redirect("/dashboard");
    }
  } catch (error) {
    console.error("Error registering user:", error);
    res.status(500).send("Internal Server Error");
  }
});

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/dashboard",
    failureRedirect: "/login",
  })
);

app.get("/logout", (req, res) => {
  req.logout();
  res.redirect("/");
});

// Global error handler
app.use((err, req, res, next) => {
  console.error("❌ Internal Server Error:", {
    message: err.message,
    stack: err.stack,
    name: err.name,
  });

  res.status(500).send(`Error: ${err.message}`);
});

// Export for Vercel
export default app;
