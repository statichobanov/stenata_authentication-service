"use strict";

const mongoose = require("mongoose");

const refreshTokenSchema = new mongoose.Schema({
  token: String,
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  expires: Date,
});

const RefreshToken = mongoose.model("RefreshToken", refreshTokenSchema);

module.exports = RefreshToken;
