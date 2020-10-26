const express = require("express");
const path = require("path");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs")
require("dotenv").config();

const app = express();

//Bring in the user model
const User = require("./models/user")

//Setup view engine
app.set("views", __dirname);
app.set("view engine", "ejs");

//Middleware
app.use(session({ secret: "cats", resave: false, saveUninitialized: true }));

//Setup LocalStrategy
passport.use(
  new LocalStrategy((username, password, done) => {
    User.findOne({ username: username }, (err, user) => {
      if (err) {
        return done(err);
      }
      if (!user) {
        return done(null, false, { msg: "Incorrect username" });
      }
      bcrypt.compare(password, user.password, (err, res) => {
        if (res) {
          // passwords match! log user in
          return done(null, user);
        } else {
          // passwords do not match!
          return done(null, false, { msg: "Incorrect password" });
        }
      });
    });
  })
);

// Middleware that gives access to the currentUser
app.use(function (req, res, next) {
  res.locals.currentUser = req.user;
  next();
});

//Sessions and Serialization
passport.serializeUser(function (user, done) {
  done(null, user.id);
});

passport.deserializeUser(function (id, done) {
  User.findById(id, function (err, user) {
    done(err, user);
  });
});

app.use(passport.initialize());
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));

//Setup DB connection
const mongoDb = process.env.MONGODB_URI;
mongoose.connect(mongoDb, {
  useNewUrlParser: true,
  useCreateIndex: true,
  useUnifiedTopology: true,
});
const db = mongoose.connection;
db.on("error", console.error.bind(console, "mongo connection error"));

//Routes
app.get("/", (req, res) => res.render("index", { user: req.user }));
app.get("/signup", (req, res) => res.render("sign-up-form"));
app.post("/signup", (req, res, next) => {
  const user = new User({
    username: req.body.username,
    password: req.body.password,
  })
  
  const passwordHash = bcrypt.hash(
    req.body.password,
    10,
    (err, hashedPassword) => {
      // if error
      if (err) throw err;
      // otherwise, store hashedPassword in DB
      user.password = hashedPassword;
      user.save((err) => {
        if (err) {
          return next(err);
        }
        res.redirect("/");
      });
    });
  })
app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/",
  })
);
app.get("/logout", (req, res) => {
  req.logout();
  res.redirect("/");
});

//Run server
app.listen(5000, () => console.log("app listening on port 5000!"));