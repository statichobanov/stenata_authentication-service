// data/repositories/userRepository.js

const User = require("../entities/User");

class UserRepository {
  async createUser(userData) {
    // Create a new user document in the database
    const newUser = new User(userData);
    await newUser.save();
    return newUser;
  }

  async findUserById(userId) {
    // Find a user by their ID
    return User.findById(userId);
  }

  async findUserByUsername(username) {
    // Find a user by their username
    return User.findOne({ username });
  }

  async findAllUsers() {
    return await User.find({}, "-password");
  }
}

module.exports = UserRepository;
