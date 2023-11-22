// adapters/ExpressAdapter.js

"use strict";

const express = require("express");
const passport = require("passport");
const cors = require("cors");
const initPassport = require("../config/passportConfig");
const authenticateToken = require("../middleware/AuthenticateToken");

class ExpressAdapter {
  constructor(userInteractor, authInteractor, refreshTokenInteractor) {
    this.userInteractor = userInteractor;
    this.authInteractor = authInteractor;
    this.refreshTokenInteractor = refreshTokenInteractor;

    /* Initialize Passport local strategy config */
    initPassport(this.userInteractor);
  }

  initConfigs(app) {
    const corsOptions = {
      origin: "http://localhost:4000",
      credentials: true,
    };

    app.use(cors(corsOptions));
    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));

    // Register routes
    app.post("/register", this.register.bind(this));
    app.post("/login", this.login.bind(this));
    app.get("/protected", authenticateToken, this.protected.bind(this));
    app.post("/logout", this.logout.bind(this));
  }

  async register(req, res) {
    try {
      const { username, password, name, email } = req.body;
      const newUser = await this.userInteractor.register({
        username,
        password,
        name,
        email,
      });

      const accessToken = this.authInteractor.generateAccessToken(newUser);
      const refreshToken =
        await this.authInteractor.generateAndSaveRefreshToken({
          userId: newUser.id,
          username: newUser.username,
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
      console.error("Error creating user:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  }

  login(req, res, next) {
    passport.authenticate(
      "local",
      { session: false },
      async (err, user, info) => {
        if (err || !user) {
          return res
            .status(401)
            .json({ message: info.message || "Authentication failed" });
        }

        const accessToken = this.authInteractor.generateAccessToken(user);
        const refreshToken =
          await this.authInteractor.generateAndSaveRefreshToken({
            userId: user.id,
            username: user.username,
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
      }
    )(req, res, next);
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
      const refreshToken = req.cookies.refreshToken;

      await this.refreshTokenInteractor.deleteRefreshToken(refreshToken);

      res.clearCookie("refreshToken", {
        httpOnly: true,
        sameSite: "None",
        secure: true,
        path: "/",
      });

      res.status(200).json({ message: "Logout successful" });
    } catch (error) {
      console.error("Error during logout:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  }
}

module.exports = ExpressAdapter;
