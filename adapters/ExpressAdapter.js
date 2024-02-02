// adapters/ExpressAdapter.js

"use strict";

const express = require("express");
const cors = require("cors");
const initPassport = require("../config/passportConfig");
const authenticateToken = require("../middleware/AuthenticateToken");
const AuthController = require("../controllers/AuthController");

class ExpressAdapter {
  constructor(userInteractor, authInteractor) {
    this.authInteractor = authInteractor;
    this.authController = new AuthController(userInteractor, authInteractor);

    /* Initialize Passport local strategy config */
    initPassport();
  }

  initConfigs(app) {
    const corsOptions = {
      origin: "http://localhost:4200",
      credentials: true,
    };

    app.use(cors(corsOptions));
    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));

    app.post("/register", (req, res, next) =>
      this.authController.register(req, res, next)
    );
    app.post("/login", (req, res, next) =>
      this.authController.login(req, res, next)
    );

    app.get(
      "/protected",
      authenticateToken(this.authInteractor),
      (req, res, next) => {
        this.authController.protected(req, res, next);
      }
    );

    app.post(
      "/logout",
      authenticateToken(this.authInteractor),
      (req, res, next) => {
        this.authController.logout(req, res, next);
      }
    );
  }
}

module.exports = ExpressAdapter;
