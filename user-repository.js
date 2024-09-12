import crypto from "node:crypto";

import DBLocal from "db-local";
import bcrypt from "bcrypt";

const { Schema } = new DBLocal({ path: "./db" });

const User = Schema("Users", {
  _id: { type: String, required: true },
  username: { type: String, required: true },
  password: { type: String, required: true },
});

export class UserRepository {
  static async create({ username, password }) {
    // Validate input
    Validation.username(username);
    Validation.password(password);

    // Check if user exists
    const user = User.findOne({ username });
    if (user) throw new Error("User already exists");

    // Create user
    const id = crypto.randomUUID();
    const hashedPassword = await bcrypt.hash(password, 10);
    User.create({ _id: id, username, password: hashedPassword }).save();

    return id;
  }
  static async login({ username, password }) {
    // Validate input
    Validation.username(username);
    Validation.password(password);

    // Check if user exists
    const user = User.findOne({ username });
    if (!user) throw new Error("User does not exist");

    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) throw new Error("Invalid password");

    const { password: _, ...publicUser } = user;

    return publicUser;
  }
}

class Validation {
  static username(username) {
    if (typeof username !== "string")
      throw new Error("Username must be a string");
    if (username.length < 3)
      throw new Error("Username must be at least 3 characters");
  }

  static password(password) {
    if (typeof password !== "string")
      throw new Error("Password must be a string");
    if (password.length < 6)
      throw new Error("Password must be at least 6 characters");
  }
}
