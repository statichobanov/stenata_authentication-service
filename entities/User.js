"use strict";

const mongoose = require("mongoose");
const bcrypt = require("bcrypt");

const userSchema = new mongoose.Schema({
  version: { type: Number, default: 1 },
  username: { type: String, unique: true, required: true },
  email: {
    type: String,
    unique: true,
    required: true,
  },
  author: { type: Boolean },
  registrationDate: { type: Date, default: Date.now },
  firstName: String,
  lastName: String,
  password: String,
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

const User = mongoose.model("User", userSchema);

module.exports = User;
