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

  async deleteAllRefreshTokens({ userId }) {
    const result = await RefreshToken.deleteMany({ userId: userId });

    /* just for info */
    if (result.deletedCount > 0) {
      console.log(
        `Deleted ${result.deletedCount} tokens for userId: ${userId}`
      );
    } else {
      console.log(`No existing tokens found for userId: ${userId}`);
    }
  }

  async findRefreshToken(userId) {
    return await RefreshToken.find({ userId: userId });
  }
}

module.exports = RefreshTokenRepository;
