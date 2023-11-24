"use strict";

const RefreshToken = require("../entities/RefreshToken");

class RefreshTokenRepository {
  async saveRefreshToken({ refreshToken, userId }) {
    const newRefreshToken = new RefreshToken({
      token: refreshToken,
      userId: userId,
      expires: new Date(Date.now() + 24 * 60 * 60 * 1000) /* One day */,
    });

    newRefreshToken.save();
  }

  async deleteRefreshToken({ userId }) {
    const deletedToken = await RefreshToken.findOneAndDelete({
      userId: userId,
    });

    /* just for info */
    if (deletedToken) {
      console.log(`Deleted existing token for userId: ${userId}`);
    } else {
      console.log(`No existing token found for userId: ${userId}`);
    }
  }

  async findRefreshToken(refreshToken) {
    return await RefreshToken.find({ token: refreshToken });
  }
}

module.exports = RefreshTokenRepository;
