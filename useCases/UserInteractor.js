"use strict";

const UserRepository = require("../repostories/UserRepository");

class UserInteractor {
  constructor() {
    this.userRepository = new UserRepository();
  }

  async register(user) {
    const { username } = user;

    try {
      const existingUser = await this.userRepository.findUserByUsername(
        username
      );

      if (existingUser) {
        throw new Error("Username already taken");
      }

      const newUser = this.userRepository.createUser(user);

      return newUser;
    } catch (error) {
      throw error;
    }
  }

  async login(email, password) {
    try {
      const user = await this.userRepository.findUserByEmail(email);

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
      return await this.userRepository.findAllUsers();
    } catch (error) {
      throw error;
    }
  }
}

module.exports = UserInteractor;
