"use strict";

const RefreshToken = require("../entities/RefreshToken");

class RefreshTokenInteractor {
  async saveRefreshToken({ refreshToken, userId }) {
    const newRefreshToken = new RefreshToken({
      token: refreshToken,
      userId: userId,
      expires: new Date(Date.now() + 24 * 60 * 60 * 1000) /* One day */,
    });

    newRefreshToken.save();
  }

  async deleteRefreshToken({ userId }) {
    await RefreshToken.findOneAndDelete({ userId: userId });

    /* just for info */
    if (deletedToken) {
      console.log(`Deleted existing token for userId: ${userId}`);
    } else {
      console.log(`No existing token found for userId: ${userId}`);
    }
  }

  async findRefreshToken({ userId }) {
    return await RefreshToken.find({ userId: userId });
  }
}

module.exports = RefreshTokenInteractor;
