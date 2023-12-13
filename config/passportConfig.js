"use strict";

const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const UserRepository = require("../repostories/UserRepository");

function initPassport() {
  passport.use(
    new LocalStrategy(
      { usernameField: "username", passwordField: "password" },
      async (username, password, done) => {
        console.log("init passport", username, password);
        try {
          const userRepository = new UserRepository();
          const user = await userRepository.findUserByUsername(username);

          if (!user || !(await user.isValidPassword(password))) {
            return done(null, false, {
              message: "Incorrect username or password",
            });
          }
          return done(null, user);
        } catch (error) {
          return done(error);
        }
      }
    )
  );
}

module.exports = initPassport;
