"use strict";

require("dotenv").config();

const MONGO_URI = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_USER_PASSWORD}@${process.env.CLUSTER}.${process.env.DB_CLOUD_URL}/${process.env.DB}?retryWrites=true&w=majority`;
console.log("Mongo uri ", MONGO_URI);
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
        console.log(
          "in new localStrategy Username password: ",
          username,
          password
        );
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

// Example middleware to extract and verify access token from the header
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) {
    return res.status(401).json({ message: "Access token is required" });
  }

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) {
      if (err.name === "TokenExpiredError") {
        const refreshToken = req.headers.cookie.refreshToken;
        // Token has expired, handle accordingly (e.g., trigger token refresh)
        return res.status(401).json({ message: "Access token has expired" });
      } else {
        // Token verification failed for reasons other than expiration
        return res.status(403).json({ message: "Invalid access token" });
      }
    }

    // Token is valid; attach user info to request
    req.user = user;
    next();
  });
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
    console.log("/register", newUser);
    // Generate JWT access token
    const accessToken = generateAccessToken(newUser);

    // Generate refresh token
    const refreshToken = generateAndSaveRefreshToken(newUser);

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      maxAge: 60 * 60 * 1000,
      sameSite: "None", // Set SameSite to 'None' for cross-site requests
      secure: true, // Set 'secure' for cross-site requests over HTTPS
      path: "/",
    });
    // Respond with tokens
    res.json({ access_token: accessToken });
  } catch (error) {
    console.error("Error creating user:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Endpoint for user login
app.post("/login", (req, res, next) => {
  passport.authenticate("local", { session: false }, (err, user, info) => {
    if (err || !user) {
      return res
        .status(401)
        .json({ message: info.message || "Authentication failed" });
    }

    // Generate JWT access token
    const accessToken = generateAccessToken(user);

    // Generate refresh token
    const refreshToken = generateAndSaveRefreshToken(user);

    // Set HTTP-only cookie with the refreshToken
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      maxAge: 60 * 60 * 1000,
      sameSite: "None", // Set SameSite to 'None' for cross-site requests
      secure: true, // Set 'secure' for cross-site requests over HTTPS
      path: "/",
    });

    // Respond with tokens
    res.header("Access-Control-Expose-Headers", "Authorization");
    // Respond with tokens
    res.json({ accessToken: accessToken });
  })(req, res, next);
});

app.get("/protected", authenticateToken, async (req, res) => {
  try {
    const users = await User.find({}, "-password"); // Exclude the password field

    res.json({
      message: "This is a protected route",
      user: req.user,
      allUsers: users,
    });
  } catch (error) {
    console.error("Error querying users:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Generate JWT access token
function generateAccessToken(user) {
  return jwt.sign(
    { sub: user.id, username: user.username },
    process.env.ACCESS_TOKEN_SECRET,
    { expiresIn: "1h" }
  );
}

// Generate refresh token
function generateAndSaveRefreshToken(user) {
  const refreshToken = jwt.sign(
    { sub: user.id },
    process.env.REFRESH_TOKEN_SECRET,
    {
      expiresIn: "1d",
    }
  );

  // Save the refresh token in the database
  const newRefreshToken = new RefreshToken({
    token: refreshToken,
    userId: user.id,
    expires: new Date(Date.now() + 24 * 60 * 60 * 1000), // Expires in 1 day
  });

  newRefreshToken.save();

  return refreshToken;
}

// Middleware to check and refresh access token using refresh token
app.get("/refresh", async (req, res) => {
  console.log("/refresh in httpsonly cookie", req.cookies);
  const refreshToken = req.cookies.refreshToken; // take from data base
  if (!refreshToken) {
    return res.status(401).json({ message: "Refresh token is required" });
  }

  try {
    // Verify refresh token
    const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);

    // Find the refresh token in the database
    const storedRefreshToken = await RefreshToken.findOne({
      token: refreshToken,
    });
    console.log("/refresh Stored refresh token in :", storedRefreshToken);
    // Check if the refresh token is still valid
    if (
      !storedRefreshToken ||
      decoded.sub !== storedRefreshToken.userId ||
      storedRefreshToken.expires < Date.now()
    ) {
      return res.status(401).json({ message: "Invalid refresh token" });
    }

    // Generate a new access token
    const user = await User.findById(decoded.sub);
    const newAccessToken = generateAccessToken(user);

    // Respond with the new access token
    res.json({ access_token: newAccessToken });
  } catch (error) {
    return res.status(401).json({ message: "Invalid refresh token" });
  }
});

// Start the server
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
