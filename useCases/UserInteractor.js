"use strict";

const User = require("../entities/User");

class UserInteractor {
  async register({ username, password, name, email }) {
    try {
      const existingUser = await User.findOne({ username });

      if (existingUser) {
        throw new Error("Username already taken");
      }

      const newUser = new User({ username, password, name, email });

      await newUser.save();

      return newUser;
    } catch (error) {
      throw error;
    }
  }

  async login(username, password) {
    try {
      const user = await User.findOne({ username });
      if (!user || !(await user.isValidPassword(password))) {
        throw new Error("Incorrect username or password");
      }

      return user;
    } catch (error) {
      throw error;
    }
  }

  async findAllUsers() {
    try {
      return await User.find({}, "-password");
    } catch (error) {
      throw error;
    }
  }
}

module.exports = UserInteractor;
