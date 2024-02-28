const mongoose = require("mongoose");
const { Schema } = mongoose;

const userSchema = new Schema(
  {
    email: {
      type: String,
      required: true,
      unique: true,
    },
    name: {
      type: String,
      required: true,
    },
    password: {
      type: String,
      required: true,
    },
    refreshToken: {
      type: String,
      required: true,
    },
    controleGear: {
      type: [String],
      index: true,
      default: [],
    },
  },
  {
    timestamps: true,
  }
);

// Define index on email field
userSchema.index({ email: 1 });

const User = mongoose.model("userSchema", userSchema);

module.exports = User;
