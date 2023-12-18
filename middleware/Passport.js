/* "use strict";

const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const User = require("../entities/User");

passport.use(
  new LocalStrategy(
    { email: "email", password: "password" },
    async (email, password, done) => {
      try {
        console.log(email);
        const user = await User.findOne({ email });
        console.log("User found by email", user);
        if (!user || !(await user.isValidPassword(password))) {
          return done(null, false, {
            message: "Incorrect email or password",
          });
        }
        return done(null, user);
      } catch (error) {
        console.log("LocalStrategy error", error);
        return done(error);
      }
    }
  )
);

module.exports = passport;
 */
