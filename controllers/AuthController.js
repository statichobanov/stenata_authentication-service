"use strict";

const passport = require("passport");

class AuthController {
  constructor(userInteractor, authInteractor) {
    this.userInteractor = userInteractor;
    this.authInteractor = authInteractor;
  }

  async register(req, res) {
    try {
      // TODO
      const newUserPayload = req.body;
      const newUser = await this.userInteractor.register(newUserPayload);

      const accessToken = this.authInteractor.generateAccessToken(newUser);
      const refreshToken = this.authInteractor.generateRefreshToken(newUser);

      await this.authInteractor.saveRefreshToken({
        userId: newUser.id,
        refreshToken: refreshToken,
      });

      res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        maxAge: 60 * 60 * 1000,
        sameSite: "None",
        secure: true,
        path: "/",
      });

      res.json({ accessToken: accessToken });
    } catch (error) {
      console.log("Error Register User:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  }

  async login(req, res, next) {
    passport.authenticate("local", { session: false }, async (err, user) => {
      console.log("Login User", user);

      if (err || !user) {
        return res
          .status(401)
          .json({ message: err || "Authentication failed" });
      }

      const accessToken = this.authInteractor.generateAccessToken(user);

      const refreshToken = this.authInteractor.generateRefreshToken(user);

      await this.authInteractor.saveRefreshToken({
        userId: user.id,
        refreshToken: refreshToken,
      });

      res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        maxAge: 60 * 60 * 1000,
        sameSite: "None",
        secure: true,
        path: "/",
      });

      res.header("Access-Control-Expose-Headers", "Authorization");

      res.json({ accessToken: accessToken });
    })(req, res, next);
  }

  async protected(req, res) {
    try {
      const users = await this.userInteractor.findAllUsers();
      if (req.accessToken) {
        res.json({
          accessToken: req.accessToken,
          message: "This is a protected route",
          user: req.user,
          allUsers: users,
        });
      } else {
        res.json({
          message: "This is a protected route",
          user: req.user,
          allUsers: users,
        });
      }
    } catch (error) {
      res.status(500).json({ message: "Internal server error" });
    }
  }

  async logout(req, res) {
    try {
      await this.authInteractor.deleteAllRefreshTokens({
        userId: req.user.sub,
      });

      res.clearCookie("refreshToken", {
        httpOnly: true,
        sameSite: "None",
        secure: true,
        path: "/",
      });

      res.status(200).json({ message: "Logout successful" });
    } catch (error) {
      console.log("Error During Logout:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  }
}

module.exports = AuthController;
