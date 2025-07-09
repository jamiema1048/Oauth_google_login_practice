const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20");
const User = require("../models/user-model");
const LocalStrategy = require("passport-local");
const bcrypt = require("bcrypt");

passport.serializeUser((user, done) => {
  console.log("Serialize User.....");
  console.log(user);
  done(null, user._id); // 將MongoDB的id，存入session
  // 並且將id簽名後，以cookie的形式給使用者
});

passport.deserializeUser(async (_id, done) => {
  console.log("Deserialize User.......");
  console.log("Use the id store by serializeUser to find data in database");
  let foundUser = await User.findOne({ _id });
  done(null, foundUser); // req.user這個屬性設定為foundUser
});

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:8000/auth/google/redirect",
    },
    async (accessToken, refreshToken, profile, done) => {
      console.log(profile);
      console.log("Came in the area of Google Strategy");
      // console.log("========================================");
      let foundUser = await User.findOne({ googleID: profile.id }).exec();
      if (foundUser) {
        console.log("User had registered, don't post in database");
        done(null, foundUser);
      } else {
        console.log("New user detected, post into database");
        let newUser = new User({
          name: profile.displayName,
          googleID: profile.id,
          thumbnail: profile.photos[0].value,
          email: profile.emails[0].value,
        });
        let savedUser = await newUser.save();
        console.log("New user created......");
        done(null, savedUser);
      }
      // User.findOrCreate({ googleId: profile.id }, function (err, user) {
      //   return cb(err, user);
      // });
    }
  )
);

passport.use(
  new LocalStrategy(async (username, password, done) => {
    let foundUser = await User.findOne({ email: username });
    if (foundUser) {
      let result = await bcrypt.compare(password, foundUser.password);
      if (result) {
        done(null, foundUser);
      } else {
        done(null, false);
      }
    } else {
      done(null, false);
    }
  })
);
