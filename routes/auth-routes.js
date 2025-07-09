const router = require("express").Router();
const passport = require("passport");
const User = require("../models/user-model");
const bcrypt = require("bcrypt");

router.get("/login", (req, res) => {
  return res.render("login", { user: req.user });
});

router.get("/logout", (req, res) => {
  req.logOut((err) => {
    if (err) return res.send(err);
    return res.redirect("/");
  });
});

router.get("/signup", (req, res) => {
  return res.render("signup", { user: req.user });
});

router.get(
  "/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
    prompt: "select_account",
  })
);

router.post("/signup", async (req, res) => {
  let { name, email, password } = req.body;
  if (name.length < 3) {
    //這段一定要寫，就算ejs已經設定minlength，如果改用Postman發送繞過ejs一樣可以設定
    req.flash("error_msg", "Ur name is too short, at least 6 cases");
    return res.redirect("/auth/signup");
  } else if (password.length > 255) {
    req.flash("error_msg", "Ur name is too long, 255 cases is the limit");
    return res.redirect("/auth/signup");
  }
  if (password.length < 8) {
    //這段一定要寫，就算ejs已經設定minlength，如果改用Postman發送繞過ejs一樣可以設定
    req.flash("error_msg", "Password too short, at least 8 cases");
    return res.redirect("/auth/signup");
  } else if (password.length > 1024) {
    req.flash("error_msg", "Password too long, 1024 cases is the limit");
    return res.redirect("/auth/signup");
  }

  // Make sure the email has signed or not
  const foundEmail = await User.findOne({ email }).exec();
  if (foundEmail) {
    req.flash("error_msg", "Email has signed.....");
    return res.redirect("/auth/signup");
  }
  let hashedPassword = await bcrypt.hash(password, 12);
  let newUser = new User({ name, email, password: hashedPassword });
  await newUser.save();
  req.flash("success_msg", "Sign up success");
  return res.redirect("/auth/login");
});

router.post(
  "/login",
  passport.authenticate("local", {
    failureRedirect: "/auth/login",
    failureFlash: "Login failure. Username or password incorrect......",
  }),
  (req, res) => {
    return res.redirect("/profile");
  }
);

router.get("/google/redirect", passport.authenticate("google"), (req, res) => {
  console.log("Start redirect area......");
  return res.redirect("/profile");
});

module.exports = router;
