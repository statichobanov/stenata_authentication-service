// adapters/ExpressAdapter.js

"use strict";

const express = require("express");
const passport = require("passport");
const cors = require("cors");
const initPassport = require("../config/passportConfig");
const authenticateToken = require("../middleware/AuthenticateToken");

class ExpressAdapter {
  constructor(userInteractor, authInteractor) {
    this.userInteractor = userInteractor;
    this.authInteractor = authInteractor;

    /* Initialize Passport local strategy config */
    initPassport();
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
    app.post("/logout", authenticateToken, this.logout.bind(this));
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
      console.error("Error creating user:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  }

  login(req, res, next) {
    passport.authenticate("local", { session: false }, async (err, user) => {
      console.log("login user", user);
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

  /* This Route is added only for testing purpose */
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
      /* const refreshToken = req.headers.cookie?.split("=")[1];
       */
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
      console.error("Error during logout:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  }
}

module.exports = ExpressAdapter;
