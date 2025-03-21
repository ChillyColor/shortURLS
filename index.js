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

const app = express();
const port = 3000;
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

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});

db.connect();

app.get("/dashboard", async (req, res) => {
  if (req.isAuthenticated()) {
    const id = req.user.id;
    const secret = await db.query(
      "SELECT short_key,original_url,user_id FROM urls WHERE user_id= $1",
      [id]
    );
    res.render("dashboard.ejs", { secret: secret.rows });
  } else {
    res.redirect("/login");
  }
});

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/submit", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("submit.ejs");
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
  "/auth/google/dashboard",
  passport.authenticate("google", {
    successRedirect: "/dashboard",
    failureRedirect: "/login",
  })
);

app.post("/delete",async (req,res)=>{
  const del =req.body.id
  await db.query("DELETE FROM urls WHERE short_key= $1",[del]);
  res.redirect("/dashboard")
})

app.post("/submit", async (req, res) => {
  const email = req.user.email;
  const link = req.body.url;
  const id = req.user.id;
  let code;
  const result = await db.query(
    "SELECT * FROM users INNER JOIN urls ON users.id = urls.user_id WHERE email=$1 AND original_url=$2",
    [email, link]
  );
  if (result.rows.length > 0) {
    code = result.rows[0].short_key;
  } else {
    code = shortid.generate();
    await db.query(
      "INSERT INTO urls (user_id,short_key,original_url) VALUES ($1,$2,$3)",
      [id, code, link]
    );
  }
  res.redirect("/dashboard");
});
app.post("/register", async (req, res) => {
  try {
    const email = req.body.username;
    const password = req.body.password;
    const result = await db.query("SELECT * FROM users WHERE email=$1", [
      email,
    ]);
    if (result.rows.length > 0) {
      res.send("You are already registered try logging in");
    } else {
      bcrypt.hash(password, saltRound, async (err, hash) => {
        if (err) {
          console.error("Error hashing password", err);
        } else {
          await db.query("INSERT INTO users (email,password) VALUES ($1,$2)", [
            email,
            hash,
          ]);
          res.redirect("/dashboard");
        }
      });
    }
  } catch (err) {
    console.log(err);
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
  req.logout(function (err) {
    if (err) {
      console.log(err);
    }
    res.redirect("/");
  });
});
app.get("/:code", async (req, res) => {
  const { code } = req.params;
  if (!req.isAuthenticated()) return res.redirect("/login");
  const id = req.user.id;
  try {
    const result = await db.query(
      "SELECT original_url FROM urls WHERE user_id=$1 AND short_key=$2",
      [id, code]
    );
    if (result.rows.length > 0) {
      res.redirect(result.rows[0].original_url);
    } else {
      res.status(404).send("Short URL Not Found");
    }
  } catch (err) {
    console.log(err);
  }
});
passport.use(
  "local",
  new Strategy(async function verify(username, password, cb) {
    try {
      const result = await db.query("SELECT * FROM users WHERE email = $1", [
        username,
      ]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const hashPassword = user.password;

        bcrypt.compare(password, hashPassword, (err, result) => {
          if (err) {
            return cb(err);
          } else {
            if (result) {
              return cb(null, user);
            } else {
              return cb(null, false);
            }
          }
        });
      } else {
        return cb(null, false);
      }
    } catch (err) {
      console.log(err);
    }
  })
);

passport.serializeUser((user, cb) => {
  cb(null, user.id); // Store only user ID in session
});

passport.deserializeUser(async (id, cb) => {
  try {
    const result = await db.query("SELECT * FROM users WHERE id=$1", [id]);
    if (result.rows.length > 0) {
      cb(null, result.rows[0]); // Retrieve full user object when needed
    } else {
      cb(null, false);
    }
  } catch (err) {
    cb(err);
  }
});
passport.use(
  "google",
  new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/dashboard",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
  },
  async(accessToken,refreshToken,profile,cb)=>{
    try{
    const result=await db.query("SELECT * FROM users WHERE email = $1",[profile.email]);
    if(result.rows.length===0){
      const newUser=await db.query("INSERT INTO users (email, password) VALUES ($1, $2)",[profile.email,profile.id]);
      return cb(null,newUser.rows[0]);
    }
    else{
      return cb(null,result.rows[0])
    }
    }catch(err){
      return cb(err);
    }
  }
)
);

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
