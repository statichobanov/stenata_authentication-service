// adapters/ExpressAdapter.js

"use strict";

const express = require("express");
const passport = require("passport");
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

    app.post(
      "/register",
      this.authController.register.bind(this.authController)
    );
    app.post("/login", this.authController.login.bind(this.authController));
    app.get(
      "/protected",
      authenticateToken(this.authInteractor),
      this.authController.protected.bind(this.authController)
    );
    app.post(
      "/logout",
      authenticateToken(this.authInteractor),
      this.authController.logout.bind(this.authController)
    );
  }
}

module.exports = ExpressAdapter;
