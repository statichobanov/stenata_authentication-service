"use strict";

/* The generateAccessToken method encapsulates the logic of creating a JWT access token.
The generateRefreshToken method encapsulates the logic of creating a JWT refresh token. */

const jwt = require("jsonwebtoken");
const RefreshTokenRepository = require("../repostories/RefreshTokenRepository");

class AuthInteractor {
  constructor() {
    this.refreshTokenRepository = new RefreshTokenRepository();
  }

  generateAccessToken({ id, username }) {
    return jwt.sign(
      { sub: id, username: username },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: "1h" }
    );
  }

  generateRefreshToken({ id, username }) {
    const refreshToken = jwt.sign(
      { sub: id, username: username },
      process.env.REFRESH_TOKEN_SECRET,
      {
        expiresIn: "1d",
      }
    );

    return refreshToken;
  }

  async saveRefreshToken(refreshTokenObject) {
    await this.refreshTokenRepository.saveRefreshToken(refreshTokenObject);
  }

  async findRefreshToken(userId) {
    return await this.refreshTokenRepository.findRefreshToken(userId);
  }

  async deleteAllRefreshTokens({ userId }) {
    await this.refreshTokenRepository.deleteAllRefreshTokens({
      userId: userId,
    });
  }
}

module.exports = AuthInteractor;
