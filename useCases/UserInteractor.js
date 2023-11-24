"use strict";

const UserRepository = require("../repostories/UserRepository");

class UserInteractor {
  constructor() {
    this.userRepository = new UserRepository();
  }

  async register({ username, password, name, email }) {
    try {
      const existingUser = await this.userRepository.findUserByUsername(
        username
      );

      if (existingUser) {
        throw new Error("Username already taken");
      }

      const newUser = this.userRepository.createUser({
        username: username,
        password: password,
        name: name,
        email: email,
      });

      return newUser;
    } catch (error) {
      throw error;
    }
  }

  async login(username, password) {
    try {
      const user = await this.userRepository.findUserByUsername(username);

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
