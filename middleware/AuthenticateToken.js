"use strict";

const jwt = require("jsonwebtoken");

function authenticateToken(authInteractor) {
  return async function (req, res, next) {
    const authHeader = req.headers["authorization"];
    const accessToken = authHeader && authHeader.split(" ")[1];
    const refreshToken = req.headers.cookie?.split("=")[1];
    console.log("cookie", req.headers.cookie);

    if (!accessToken || !refreshToken) {
      return res.status(401).json({ message: "Missing Token" });
    }

    const decodedRefreshToken = jwt.verify(
      refreshToken,
      process.env.REFRESH_TOKEN_SECRET
    );

    // TODO: think if it is possible to find token only with userid since we delete all asocciated refreshTokens on logout
    const refreshTokenDBObject = await authInteractor.findRefreshToken(
      refreshToken
    );
    const refreshTokenDB = refreshTokenDBObject[0];

    if (!refreshTokenDB) {
      return res.status(403).json({ message: "Invalid refresh token" });
    }

    if (
      refreshTokenDB.token !== refreshToken ||
      refreshTokenDB.expires < Date.now()
    ) {
      return res.status(401).json({ message: "Invalid refresh token" });
    }

    jwt.verify(
      accessToken,
      process.env.ACCESS_TOKEN_SECRET,
      async (err, user) => {
        if (err) {
          if (err.name === "TokenExpiredError") {
            const newAccessToken = await authInteractor.generateAccessToken({
              id: decodedRefreshToken.sub,
              username: decodedRefreshToken.username,
            });

            req.accessToken = newAccessToken;
            req.user = {
              id: decodedRefreshToken.sub,
              username: decodedRefreshToken.username,
            };
            next();
          } else {
            return res.status(403).json({ message: "Invalid access token" });
          }
        } else {
          req.user = user;
          next();
        }
      }
    );
  };
}

module.exports = authenticateToken;
