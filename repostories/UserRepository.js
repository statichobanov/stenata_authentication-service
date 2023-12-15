// data/repositories/userRepository.js

const User = require("../entities/User");

class UserRepository {
  async createUser(userData) {
    const newUser = new User(userData);

    await newUser.save();

    return newUser;
  }

  async findUserById(userId) {
    return User.findById(userId);
  }

  async findUserByUsername(username) {
    return User.findOne({ username });
  }

  async findUserByEmail(email) {
    return User.findOne({ email });
  }

  async findAllUsers() {
    return await User.find({}, "-password");
  }
}

module.exports = UserRepository;
