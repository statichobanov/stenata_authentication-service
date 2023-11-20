"use strict";

const jwt = require("jsonwebtoken");

class AuthInteractor {
  generateAccessToken({ id, username }) {
    return jwt.sign(
      { sub: id, username: username },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: "1h" }
    );
  }

  generateRefreshToken({ userId, username }) {
    const refreshToken = jwt.sign(
      { sub: userId, username: username },
      process.env.REFRESH_TOKEN_SECRET,
      {
        expiresIn: "1d",
      }
    );

    return refreshToken;
  }
}

module.exports = AuthInteractor;
