"use strict";

const jwt = require("jsonwebtoken");
const AuthInteractor = require("../useCases/AuthInteractor");

async function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const accessToken = authHeader && authHeader.split(" ")[1];
  const refreshToken = req.headers.cookie?.split("=")[1];
  console.log("authenticateToken: ", accessToken, refreshToken);
  const authInteractor = new AuthInteractor();

  if (!accessToken || !refreshToken) {
    return res.status(401).json({ message: "Missing Token" });
  }

  const decodedRefreshToken = jwt.verify(
    refreshToken,
    process.env.REFRESH_TOKEN_SECRET
  );
  let refreshTokenDBObject = await authInteractor.findRefreshToken(
    refreshToken
  );

  if (!refreshTokenDBObject[0]) {
    return res.status(403).json({ message: "Invalid refresh token" });
  }

  if (
    refreshTokenDBObject[0].token !== refreshToken ||
    refreshTokenDBObject[0].expires < Date.now()
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
}

module.exports = authenticateToken;
