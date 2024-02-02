"use strict";

const jwt = require("jsonwebtoken");

function authenticateToken(authInteractor) {
  return async function (req, res, next) {
    const authHeader = req.headers["authorization"];
    const accessToken = authHeader && authHeader.split(" ")[1];

    if (!accessToken) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const decodedAccessToken = jwt.verify(
      accessToken,
      process.env.ACCESS_TOKEN_SECRET,
      { ignoreExpiration: true }
    );

    jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET, async (err) => {
      const refreshTokenDBObject = await authInteractor.findRefreshToken(
        decodedAccessToken.sub
      );

      const refreshTokenDB = refreshTokenDBObject[0];

      if (!refreshTokenDB) {
        return res.status(401).json({ message: "Unauthorized" });
      }

      if (err) {
        console.log(err.name);
        if (err.name === "TokenExpiredError") {
          if (refreshTokenDB.expires < Date.now()) {
            return res.status(401).json({ message: "Unauthorized" });
          }

          const newAccessToken = await authInteractor.generateAccessToken({
            id: decodedAccessToken.sub,
            username: decodedAccessToken.username,
          });

          req.accessToken = newAccessToken;
          req.user = {
            id: decodedAccessToken.sub,
            username: decodedAccessToken.username,
          };
          next();
        } else {
          return res.status(403).json({ message: "Invalid access token" });
        }
      } else {
        const { sub: userId, username } = decodedAccessToken;
        req.user = { id: userId, username };

        next();
      }
    });
  };
}

module.exports = authenticateToken;
