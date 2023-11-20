"use strict";

require("dotenv").config();

const MONGO_URI = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_USER_PASSWORD}@${process.env.CLUSTER}.${process.env.DB_CLOUD_URL}/${process.env.DB}?retryWrites=true&w=majority`;

const express = require("express");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt"); // For securely hashing passwords
const cors = require("cors");
const cookieParser = require("cookie-parser");

const app = express();
const port = 3000;

const corsOptions = {
  origin: "http://localhost:4000",
  credentials: true,
};

app.use(cors(corsOptions));

try {
  mongoose.connect(MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  });
} catch (error) {
  console.log("ERROR Connecting to mongo db: ", error);
}

// User model with password hashing
const userSchema = new mongoose.Schema({
  username: String,
  password: String,
  name: String,
  email: String,
});

userSchema.pre("save", async function (next) {
  try {
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(this.password, salt);
    this.password = hashedPassword;
    next();
  } catch (error) {
    next(error);
  }
});

userSchema.methods.isValidPassword = async function (password) {
  try {
    return await bcrypt.compare(password, this.password);
  } catch (error) {
    throw error;
  }
};

// Refresh token model
const refreshTokenSchema = new mongoose.Schema({
  token: String,
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  expires: Date,
});

const User = mongoose.model("User", userSchema);
const RefreshToken = mongoose.model("RefreshToken", refreshTokenSchema);

// Middleware for parsing JSON in requests
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
// Passport configuration
passport.use(
  new LocalStrategy(
    { usernameField: "username", passwordField: "password" },
    async (username, password, done) => {
      try {
        const user = await User.findOne({ username });
        if (!user || !(await user.isValidPassword(password))) {
          return done(null, false, {
            message: "Incorrect username or password",
          });
        }
        return done(null, user);
      } catch (error) {
        return done(error);
      }
    }
  )
);

// Serialize and deserialize user for session support (optional)
/* passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  User.findById(id, (err, user) => {
    done(err, user);
  });
});
 */

const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const accessToken = authHeader && authHeader.split(" ")[1];
  const refreshToken = req.headers.cookie?.split("=")[1];

  if (!accessToken || !refreshToken) {
    return res.status(401).json({ message: "Missing Token" });
  }

  const decodedRefreshToken = jwt.verify(
    refreshToken,
    process.env.REFRESH_TOKEN_SECRET
  );

  const refreshTokenDBObject = await RefreshToken.findOne({
    userId: decodedRefreshToken.sub,
  });

  if (!refreshTokenDBObject) {
    return res.status(403).json({ message: "ebi si maikata" });
  }

  jwt.verify(
    accessToken,
    process.env.ACCESS_TOKEN_SECRET,
    async (err, user) => {
      if (err) {
        /* Access Token has expired, try to get a new access token using the refresh token from cookies */
        if (err.name === "TokenExpiredError") {
          const refreshToken = req.headers.cookie.split("=")[1];

          if (!refreshToken) {
            return res.status(401).json({ message: "Missing Refresh Token" });
          }

          try {
            // Verify refresh token
            const decodedRefreshToken = jwt.verify(
              refreshToken,
              process.env.REFRESH_TOKEN_SECRET
            );

            // Check if the refresh token is still valid
            const refreshTokenDBObject = await RefreshToken.findOne({
              userId: decodedRefreshToken.sub,
              token: refreshToken,
            });

            if (
              refreshTokenDBObject?.token !== refreshToken ||
              refreshTokenDBObject?.expires < Date.now()
            ) {
              return res.status(401).json({ message: "Invalid refresh token" });
            }

            const newAccessToken = generateAccessToken({
              id: decodedRefreshToken.sub,
              username: decodedRefreshToken.username,
            });

            req.accessToken = newAccessToken;
            req.user = {
              id: decodedRefreshToken.sub,
              username: decodedRefreshToken.username,
            };
            next();
          } catch (refreshError) {
            return res.status(401).json({ message: "Failed to refresh token" });
          }
        } else {
          // Token verification failed for reasons other than expiration
          return res.status(403).json({ message: "Invalid access token" });
        }
      } else {
        // Token is valid; attach user info to request
        req.user = user;
        next();
      }
    }
  );
};

// Endpoint for user registration
app.post("/register", async (req, res) => {
  const { username, password, name, email } = req.body;

  try {
    // Check if the username is already taken
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ message: "Username already taken" });
    }

    // Create a new user
    const newUser = new User({ username, password, name, email });

    await newUser.save();

    // Generate JWT access token
    const accessToken = generateAccessToken(newUser);

    // Generate refresh token
    const refreshToken = await generateAndSaveRefreshToken(newUser);

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      maxAge: 60 * 60 * 1000,
      sameSite: "None", // Set SameSite to 'None' for cross-site requests
      secure: true, // Set 'secure' for cross-site requests over HTTPS
      path: "/",
    });
    // Respond with tokens
    res.json({ accessToken: accessToken });
  } catch (error) {
    console.error("Error creating user:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/login", (req, res, next) => {
  passport.authenticate(
    "local",
    { session: false },
    async (err, user, info) => {
      if (err || !user) {
        return res
          .status(401)
          .json({ message: info.message || "Authentication failed" });
      }

      // Generate JWT access token
      const accessToken = generateAccessToken(user);

      // Generate refresh token
      const refreshToken = await generateAndSaveRefreshToken({
        userId: user.id,
        username: user.username,
      });

      res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        maxAge: 60 * 60 * 1000,
        sameSite: "None", // Set SameSite to 'None' for cross-site requests
        secure: true, // Set 'secure' for cross-site requests over HTTPS
        path: "/",
      });

      res.header("Access-Control-Expose-Headers", "Authorization");

      res.json({ accessToken: accessToken });
    }
  )(req, res, next);
});

app.get("/protected", authenticateToken, async (req, res) => {
  console.log("req.user /protected", req.user, req.accessToken);
  try {
    const users = await User.find({}, "-password"); // Exclude the password field
    /* this means authenticateToken middleware has generated a new accessToken */
    if (req.accessToken) {
      res.json({
        accessToken: req.accessToken,
        message: "This is a protected route",
        user: res.user,
        allUsers: users,
      });
    } else {
      res.json({
        message: "This is a protected route",
        user: req.user,
        allUsers: users,
      });
    }
  } catch (error) {
    res.status(500).json({ message: "Internal server error" });
  }
});

// Generate JWT access token
function generateAccessToken({ id, username }) {
  return jwt.sign(
    { sub: id, username: username },
    process.env.ACCESS_TOKEN_SECRET,
    { expiresIn: "1h" }
  );
}

// Generate refresh token
async function generateAndSaveRefreshToken({ userId, username }) {
  const refreshToken = jwt.sign(
    { sub: userId, username: username },
    process.env.REFRESH_TOKEN_SECRET,
    {
      expiresIn: "1d",
    }
  );
  await saveRefreshToken({ refreshToken, userId });
  return refreshToken;
}

async function saveRefreshToken({ refreshToken, userId }) {
  await RefreshToken.findOneAndDelete({ userId: userId });

  const newRefreshToken = new RefreshToken({
    token: refreshToken,
    userId: userId,
    expires: new Date(Date.now() + 24 * 60 * 60 * 1000), // Expires in 1 day
  });

  newRefreshToken.save();
}
app.post("/logout", async (req, res) => {
  try {
    const refreshToken = req.cookies.refreshToken;

    // Clear the refresh token from the database
    await RefreshToken.findOneAndDelete({ token: refreshToken });

    // Clear the refresh token cookie on the client side
    res.clearCookie("refreshToken", {
      httpOnly: true,
      sameSite: "None",
      secure: true,
      path: "/",
    });

    res.status(200).json({ message: "Logout successful" });
  } catch (error) {
    console.error("Error during logout:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Start the server
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
